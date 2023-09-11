{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Root (
    refreshRoot,
    rootPriming,
    cachedDNSKEY,
    takeDEntryIPs,
    rootHint,
) where

-- GHC packages
import Data.IORef (atomicWriteIORef, readIORef)
import qualified Data.Set as Set

-- other packages

-- dnsext packages
import DNS.Do53.Memo (
    rankedAdditional,
    rankedAnswer,
 )
import qualified DNS.Log as Log
import DNS.SEC
import qualified DNS.SEC.Verify as SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))
import System.Console.ANSI.Types

-- this package
import DNS.Cache.Imports
import DNS.Cache.Iterative.Cache
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Norec
import DNS.Cache.Iterative.Random
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Cache.Iterative.Verify as Verify
import DNS.Cache.RootServers (rootServers)
import DNS.Cache.RootTrustAnchors (rootSepDS)
import DNS.Cache.Types (NE)

refreshRoot :: DNSQuery Delegation
refreshRoot = do
    curRef <- lift $ asks currentRoot_
    let refresh = do
            n <- getRoot
            liftIO $ atomicWriteIORef curRef $ Just n
            return n
        keep = do
            current <- liftIO $ readIORef curRef
            maybe refresh return current
        checkLife = do
            nsc <- lift $ lookupCache "." NS
            maybe refresh (const keep) nsc
    checkLife
  where
    getRoot = do
        let fallback s = lift $ do
                {- fallback to rootHint -}
                logLn Log.WARN $ "refreshRoot: " ++ s
                return rootHint
        either fallback return =<< rootPriming

{-
steps of root priming
1. get DNSKEY RRset of root-domain using `cachedDNSKEY` steps
2. query NS from root-domain with DO flag - get NS RRset and RRSIG
3. verify NS RRset of root-domain with RRSIGa
 -}
rootPriming :: DNSQuery (Either String Delegation)
rootPriming = do
    disableV6NS <- lift $ asks disableV6NS_
    ips <- selectIPs 4 $ takeDEntryIPs disableV6NS hintDes
    lift . logLn Log.DEMO . unwords $ "root-server addresses for priming:" : [show ip | ip <- ips]
    body ips
  where
    left s = pure $ Left $ "rootPriming: " ++ s
    logResult delegationNS color s = do
        clogLn Log.DEMO (Just color) $ "root-priming: " ++ s
        putDelegation PPShort delegationNS (logLn Log.DEMO) (logLn Log.DEBUG . ("zone: \".\":\n" ++))
    nullNS = left "no NS RRs"
    ncNS = left "not canonical NS RRs"
    pairNS rr = (,) <$> rdata rr `DNS.rdataField` DNS.ns_domain <*> pure rr
    verify dnskeys msgNS = Verify.withCanonical dnskeys rankedAnswer msgNS "." NS pairNS nullNS ncNS $
        \nsps nsRRset cacheNS -> do
            let nsSet = Set.fromList $ map fst nsps
                (axRRs, cacheAX) = withSection rankedAdditional msgNS $ \rrs rank ->
                    (axList False (`Set.member` nsSet) (\_ rr -> rr) rrs, cacheSection axRRs rank)
            case findDelegation nsps axRRs of
                Nothing -> left "no delegation"
                Just k | not $ rrsetValid nsRRset -> do
                    logResult (delegationNS $ k [rootSepDS]) Red "verification failed - RRSIG of NS: \".\""
                    left "DNSSEC verification failed"
                Just k | Delegation{..} <- k [rootSepDS] -> do
                    cacheNS *> cacheAX
                    logResult delegationNS Green "verification success - RRSIG of NS: \".\""
                    pure $ Right $ Delegation delegationZone delegationNS delegationDS dnskeys

    body ips = runExceptT $ do
        dnskeys <- either (throwE . ("rootPriming: " ++)) pure =<< lift (cachedDNSKEY [rootSepDS] ips ".")
        msgNS <- lift $ norec True ips "." NS
        ExceptT $ lift $ verify dnskeys msgNS

    Delegation _dot hintDes _ _ = rootHint

{-
steps to get verified and cached DNSKEY RRset
1. query DNSKEY from delegatee with DO flag - get DNSKEY RRset and its RRSIG
2. verify SEP DNSKEY of delegatee with DS
3. verify DNSKEY RRset of delegatee with RRSIG
4. cache DNSKEY RRset with RRSIG when validation passes
 -}
cachedDNSKEY :: [RD_DS] -> [IP] -> Domain -> DNSQuery (Either String [RD_DNSKEY])
cachedDNSKEY [] _ _ = pure $ Left "cachedDSNKEY: no DS entry"
cachedDNSKEY dss aservers dom = do
    msg <- norec True aservers dom DNSKEY
    let rcode = DNS.rcode $ DNS.flags $ DNS.header msg
    case rcode of
        DNS.NoErr -> withSection rankedAnswer msg $ \srrs _rank ->
            either (pure . Left) (verifyDNSKEY msg) $ verifySEP dss dom srrs
        _ -> pure $ Left $ "cachedDNSKEY: error rcode to get DNSKEY: " ++ show rcode
  where
    cachedResult krds dnskeyRRset cacheDNSKEY
        | rrsetValid dnskeyRRset = lift cacheDNSKEY $> Right krds {- only cache DNSKEY RRset on verification successs -}
        | otherwise = pure $ Left $ "cachedDNSKEY: no verified RRSIG found: " ++ show (rrsMayVerified dnskeyRRset)
    verifyDNSKEY msg sepps = do
        let dnskeyRD rr = DNS.fromRData $ rdata rr :: Maybe RD_DNSKEY
            nullDNSKEY = pure $ Left "cachedDNSKEY: null" {- guarded by verifySEP, null case, SEP is null too -}
            ncDNSKEY = pure $ Left "cachedDNSKEY: not canonical"
        Verify.with (map fst sepps) rankedAnswer msg dom DNSKEY dnskeyRD nullDNSKEY ncDNSKEY cachedResult

verifySEP
    :: [RD_DS]
    -> Domain
    -> [ResourceRecord]
    -> Either String [(RD_DNSKEY, RD_DS)]
verifySEP dss dom rrs = do
    let dnskeys = rrListWith DNSKEY DNS.fromRData dom (,) rrs
        seps =
            [ (key, ds)
            | (key, _) <- dnskeys
            , ds <- dss
            , Right () <- [SEC.verifyDS dom key ds]
            ]
    when (null seps) $ Left "verifySEP: no DNSKEY matches with DS"
    pure seps

-- {-# ANN rootHint ("HLint: ignore Use tuple-section") #-}
rootHint :: Delegation
rootHint =
    maybe (error "rootHint: bad configuration.") ($ []) $ findDelegation (nsList "." (,) ns) as
  where
    (ns, as) = rootServers

takeDEntryIPs :: Bool -> NE DEntry -> [IP]
takeDEntryIPs disableV6NS des = unique $ foldr takeDEntryIP [] (fst des : snd des)
  where
    unique = Set.toList . Set.fromList
    takeDEntryIP (DEonlyNS{}) xs = xs
    takeDEntryIP (DEwithAx _ ip@(IPv4{})) xs = ip : xs
    takeDEntryIP (DEwithAx _ ip@(IPv6{})) xs
        | disableV6NS = xs
        | otherwise = ip : xs
