{-# LANGUAGE DeriveTraversable #-}

module DNS.Cache.Iterative.Delegation (
    lookupDelegation,
    delegationWithCache,
    MayDelegation,
    noDelegation,
    hasDelegation,
    mayDelegation,
) where

-- GHC packages
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Reader (asks)
import Data.Function (on)
import Data.Functor (($>))
import Data.List (groupBy, sort, uncons)
import qualified Data.Set as Set

-- other packages
import System.Console.ANSI.Types

-- dns packages
import DNS.Do53.Memo (
    rankedAdditional,
    rankedAuthority,
 )
import DNS.SEC (
    RD_DNSKEY,
    TYPE (DS),
 )
import DNS.Types (
    DNSMessage,
    Domain,
    ResourceRecord (..),
    TYPE (A, AAAA, NS),
 )
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))

-- this package
import DNS.Cache.Iterative.Cache
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Cache.Iterative.Verify as Verify
import qualified DNS.Log as Log

newtype GMayDelegation a
    = MayDelegation (Maybe a)
    deriving (Functor, Foldable, Traversable)

type MayDelegation = GMayDelegation Delegation

noDelegation :: MayDelegation
noDelegation = MayDelegation Nothing

hasDelegation :: Delegation -> MayDelegation
hasDelegation = MayDelegation . Just

mayDelegation :: a -> (Delegation -> a) -> MayDelegation -> a
mayDelegation n h (MayDelegation m) = maybe n h m

-- If Nothing, it is a miss-hit against the cache.
-- If Just NoDelegation, cache hit but no delegation information.
lookupDelegation :: Domain -> ContextT IO (Maybe MayDelegation)
lookupDelegation dom = do
    disableV6NS <- asks disableV6NS_
    let lookupDEs ns = do
            let deListA = rrListWith A (`DNS.rdataField` DNS.a_ipv4) ns (\v4 _ -> DEwithAx ns (IPv4 v4))
                deListAAAA = rrListWith AAAA (`DNS.rdataField` DNS.aaaa_ipv6) ns (\v6 _ -> DEwithAx ns (IPv6 v6))

            lk4 <- fmap (deListA . fst) <$> lookupCache ns A
            lk6 <- fmap (deListAAAA . fst) <$> lookupCache ns AAAA
            return $ case lk4 <> lk6 of
                Nothing
                    | ns `DNS.isSubDomainOf` dom -> [] {- miss-hit with sub-domain case cause iterative loop, so return null to skip this NS -}
                    | otherwise -> [DEonlyNS ns {- the case both A and AAAA are miss-hit -}]
                Just as -> as {- just return address records. null case is wrong cache, so return null to skip this NS -}
        noCachedV4NS es = disableV6NS && null (v4DEntryList es)
        fromDEs es
            | noCachedV4NS es = Nothing
            {- all NS records for A are skipped under disableV6NS, so handle as miss-hit NS case -}
            | otherwise =
                (\des -> hasDelegation $ Delegation dom des [] []) <$> uncons es
        {- Nothing case, all NS records are skipped, so handle as miss-hit NS case -}
        getDelegation :: ([ResourceRecord], a) -> ContextT IO (Maybe MayDelegation)
        getDelegation (rrs, _) = do
            {- NS cache hit -}
            let nss = sort $ nsList dom const rrs
            case nss of
                [] -> return $ Just noDelegation {- hit null NS list, so no delegation -}
                _ : _ -> fromDEs . concat <$> mapM lookupDEs nss

    maybe (return Nothing) getDelegation =<< lookupCache dom NS

v4DEntryList :: [DEntry] -> [DEntry]
v4DEntryList [] = []
v4DEntryList des@(de : _) = concatMap skipAAAA $ byNS des
  where
    byNS = groupBy ((==) `on` nsDomain)
    skipAAAA = nullCase . filter (not . aaaaDE)
      where
        aaaaDE (DEwithAx _ (IPv6{})) = True
        aaaaDE _ = False
        nullCase [] = [DEonlyNS (nsDomain de)]
        nullCase es@(_ : _) = es

nsDomain :: DEntry -> Domain
nsDomain (DEwithAx dom _) = dom
nsDomain (DEonlyNS dom) = dom

-- Caching while retrieving delegation information from the authoritative server's reply
delegationWithCache
    :: Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> DNSQuery MayDelegation
delegationWithCache zoneDom dnskeys dom msg = do
    (verifyMsg, verifyColor, raiseOnFailure, dss, cacheDS) <- lift verify
    let found x = do
            cacheDS
            cacheNS
            cacheAdds
            clogLn Log.DEMO verifyColor $ verifyMsg ++ ": " ++ domTraceMsg
            clogLn Log.DEMO Nothing $ ppDelegation (delegationNS x)
            return x

    raiseOnFailure
    lift . maybe (notFound $> noDelegation) (fmap hasDelegation . found) $
        takeDelegationSrc nsps dss adds {- There is delegation information only when there is a selectable NS -}
  where
    fromDS = DNS.fromRData . rdata

    verify = Verify.withCanonical dnskeys rankedAuthority msg dom DS fromDS nullDS notCanonical canonical

    nullDS = pure ("delegation - no DS, so no verify", Just Yellow, pure (), [], pure ())
    canonical dsrds dsRRset cacheDS
        | rrsetVerified dsRRset = pure ("delegation - verification success - RRSIG of DS", Just Green, pure (), dsrds, cacheDS)
        | otherwise = pure ("delegation - verification failed - RRSIG of DS", Just Red, throwDnsError DNS.ServerFailure, [], cacheDS)
    notCanonical = pure ("delegation - not canonical DS", Just Red, throwDnsError DNS.ServerFailure, [], pure ())

    notFound = clogLn Log.DEMO Nothing $ "no delegation: " ++ domTraceMsg

    domTraceMsg = show zoneDom ++ " -> " ++ show dom

    (nsps, cacheNS) = withSection rankedAuthority msg $ \rrs rank ->
        let nsps_ = nsList dom (,) rrs in (nsps_, cacheNoRRSIG (map snd nsps_) rank)

    (adds, cacheAdds) = withSection rankedAdditional msg $ \rrs rank ->
        let axs = filter match rrs in (axs, cacheSection axs rank)
      where
        match rr = rrtype rr `elem` [A, AAAA] && rrname rr `Set.member` nsSet
        nsSet = Set.fromList $ map fst nsps
