{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Verify (verifyAndCache) where

-- GHC packages
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Reader (asks)
import DNS.Types.Decode (EpochTime)

-- other packages

-- dns packages
import DNS.Do53.Memo (Ranking)
import DNS.SEC (
    RD_DNSKEY,
    RD_RRSIG (..),
    TYPE,
    fromDNSTime,
    toDNSTime,
 )
import qualified DNS.SEC.Verify as SEC
import DNS.Types (
    CLASS,
    Domain,
    RData,
    ResourceRecord (..),
    TTL,
 )
import qualified DNS.Types as DNS
import qualified DNS.Types.Internal as DNS

-- this package
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Log as Log

verifyAndCache
    :: [RD_DNSKEY]
    -> [ResourceRecord]
    -> [(RD_RRSIG, TTL)]
    -> Ranking
    -> ContextT IO (RRset, ContextT IO ())
verifyAndCache _ [] _ _ = return (rrsetEmpty, return ())
verifyAndCache dnskeys rrs@(_ : _) sigs rank = do
    now <- liftIO =<< asks currentSeconds_
    let crrsError [] _ = return (rrsetEmpty, return ())
        crrsError (_ : _) _ = do
            logLines Log.WARN $ "verifyAndCache: no caching RR set:" : map (("\t" ++) . show) rrs
            return (rrsetEmpty, return ())
    withVerifiedRRset now dnskeys rrs sigs crrsError $
        \_sortedRRs dom typ cls minTTL rds sigrds ->
            return (RRset dom typ cls minTTL rds sigrds, cacheRRset rank dom typ cls minTTL rds sigrds)

verifyAndCache'
    :: [RD_DNSKEY]
    -> (RRset, [DNS.SPut ()])
    -> [(RD_RRSIG, TTL)]
    -> Ranking
    -> ContextT IO (RRset, ContextT IO ())
verifyAndCache' dnskeys rrsp@(rrset, _) sigs rank
    | null dnskeys = return (rrset, cacheNotVerified rrset) {- not verify for null dnskeys -}
    | null sigs = return (rrset, cacheNotVerified rrset) {- not verify for null rrsigs -}
    | otherwise = do
          now <- liftIO =<< asks currentSeconds_
          withVerifiedRRset' now dnskeys rrsp sigs $
              \dom typ cls minTTL rds sigrds ->
                  return (RRset dom typ cls minTTL rds sigrds, cacheRRset rank dom typ cls minTTL rds sigrds)
  where
    cacheNotVerified RRset{..} = cacheRRset rank rrsName rrsType rrsClass rrsTTL rrsRDatas Nothing


{- `left` is not RRset case. `right` is just RRset case.
   `[RD_RRSIG]` is not null on verification success case. -}
withVerifiedRRset
    :: EpochTime
    -> [RD_DNSKEY]
    -> [ResourceRecord]
    -> [(RD_RRSIG, TTL)]
    -> ([ResourceRecord] -> String -> a)
    -> ([ResourceRecord] -> Domain -> TYPE -> CLASS -> TTL -> [RData] -> Maybe [RD_RRSIG] -> a)
    -> a
withVerifiedRRset now dnskeys rrs sigs left right =
    either (left sortedRRs) ($ rightK) $ SEC.canonicalRRsetSorted sortedRRs
  where
    rightK dom typ cls ttl rds = right sortedRRs dom typ cls minTTL rds goodSigRDs
      where
        goodSigs =
            [ rrsig
            | rrsig@(sigrd, _) <- sigs
            , key <- dnskeys
            , Right () <- [SEC.verifyRRSIGsorted (toDNSTime now) key sigrd typ ttl sortedWires]
            ]
        (sigrds, sigTTLs) = unzip goodSigs
        goodSigRDs
            | null sigs = Nothing {- no way to verify  -}
            {-- | null dnskeys = ??  --}
            {- TODO: null dnskeys case -}
            | otherwise = Just sigrds
        expireTTLs = [exttl | sig <- sigrds, let exttl = fromDNSTime (rrsig_expiration sig) - now, exttl > 0]
        minTTL = minimum $ ttl : sigTTLs ++ map fromIntegral expireTTLs
    (sortedWires, sortedRRs) = unzip $ SEC.sortCanonical rrs

withVerifiedRRset'
    :: EpochTime
    -> [RD_DNSKEY]
    -> (RRset, [DNS.SPut ()])
    -> [(RD_RRSIG, TTL)]
    -> (Domain -> TYPE -> CLASS -> TTL -> [RData] -> Maybe [RD_RRSIG] -> a)
    -> a
withVerifiedRRset' now dnskeys (RRset{..}, sortedWires) sigs vk =
    vk rrsName typ rrsClass minTTL rrsRDatas goodSigRDs
  where
    ttl = rrsTTL
    typ = rrsType
    goodSigs =
        [ rrsig
        | rrsig@(sigrd, _) <- sigs
        , key <- dnskeys
        , Right () <- [SEC.verifyRRSIGsorted (toDNSTime now) key sigrd typ ttl sortedWires]
        ]
    (sigrds, sigTTLs) = unzip goodSigs
    goodSigRDs
        | null sigs = Nothing {- no way to verify  -}
        | null dnskeys = Nothing
        | otherwise = Just sigrds {- not null on verification success case. -}
    expireTTLs = [exttl | sig <- sigrds, let exttl = fromDNSTime (rrsig_expiration sig) - now, exttl > 0]
    minTTL = minimum $ ttl : sigTTLs ++ map fromIntegral expireTTLs

{- take not verified RRset -}
takeRRset :: [ResourceRecord] -> Either String (RRset, [DNS.SPut ()])
takeRRset rrs =
  either Left (Right . ($ rightK)) $ SEC.canonicalRRsetSorted sortedRRs
  where
    rightK dom typ cls ttl rds = (RRset dom typ cls ttl rds Nothing, sortedWires)
    (sortedWires, sortedRRs) = unzip $ SEC.sortCanonical rrs

rrsetEmpty :: RRset
rrsetEmpty = RRset "" (DNS.toTYPE 0) 0 0 [] Nothing

cacheRRset
    :: Ranking
    -> Domain
    -> TYPE
    -> CLASS
    -> TTL
    -> [RData]
    -> Maybe [RD_RRSIG]
    -> ContextT IO ()
cacheRRset rank dom typ cls ttl rds _sigrds = do
    insertRRSet <- asks insert_
    logLn Log.DEBUG $ "cacheRRset: " ++ show (((dom, typ, cls), ttl), rank) ++ "  " ++ show rds
    liftIO $ insertRRSet (DNS.Question dom typ cls) ttl (Right rds) rank {- TODO: cache with RD_RRSIG -}
