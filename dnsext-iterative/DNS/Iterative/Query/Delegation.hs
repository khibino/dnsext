{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Delegation (
    delegationIPs,
    fillsDNSSEC,
    servsChildZone,
    ---
    lookupDelegation,
    delegationWithCache,
    fillCachedDelegation,
    MayDelegation,
    noDelegation,
    hasDelegation,
    mayDelegation,
) where

-- GHC packages
import qualified Data.List.NonEmpty as NE
import qualified Data.Set as Set

-- other packages

-- dnsext packages
import qualified DNS.Log as Log
import DNS.RRCache (
    rankedAdditional,
    rankedAnswer,
    rankedAuthority,
 )
import qualified DNS.RRCache as Cache
import DNS.SEC
import qualified DNS.SEC.Verify as SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP, IPv4, IPv6)
import System.Console.ANSI.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Norec
import DNS.Iterative.Query.Root
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
import qualified DNS.Iterative.Query.Verify as Verify

---- import for doctest
import DNS.Iterative.Query.TestEnv

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> :seti -Wno-incomplete-uni-patterns
-- >>> import qualified DNS.Types.Opaque as Opaque
-- >>> import DNS.SEC
-- >>> DNS.runInitIO addResourceDataForDNSSEC

-- test env use from doctest
_newTestEnv :: IO Env
_newTestEnv = newTestEnvNoCache (const $ pure ()) True

---

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

---

{- Workaround delegation for one authoritative server has both domain zone and sub-domain zone -}
servsChildZone :: Delegation -> Domain -> DNSMessage -> DNSQuery MayDelegation
servsChildZone nss dom msg =
    handleSOA (handleASIG $ pure noDelegation)
  where
    handleSOA fallback = withSection rankedAuthority msg $ \srrs rank -> do
        let soaRRs = rrListWith SOA soaRD dom (\_ rr -> rr) srrs
        getSec <- lift $ asks currentSeconds_
        case soaRRs of
            [] -> fallback
            [_] -> getWorkaround >>= verifySOA getSec
            _ : _ : _ -> multipleSOA rank soaRRs
      where
        soaRD rd = DNS.fromRData rd :: Maybe DNS.RD_SOA
        multipleSOA rank soaRRs = do
            lift . logLn Log.WARN $ "servsChildZone: " ++ show dom ++ ": multiple SOAs are found:"
            lift . logLn Log.DEMO $ show dom ++ ": multiple SOA: " ++ show soaRRs
            failWithCacheOrigQ rank DNS.ServerFailure
        verifySOA getSec wd
            | null dnskeys = pure $ hasDelegation wd
            | otherwise = Verify.cases getSec zone dnskeys rankedAuthority msg dom SOA (soaRD . rdata) nullSOA ncSOA result
          where
            zone = delegationZone wd
            dnskeys = delegationDNSKEY wd
            nullSOA = pure noDelegation {- guarded by soaRRs [] case -}
            ncSOA _ncLog = pure noDelegation {- guarded by soaRRs [_] case. single record must be canonical -}
            result _ soaRRset _cacheSOA
                | rrsetValid soaRRset = pure $ hasDelegation wd
                | otherwise = verificationError
    handleASIG fallback = withSection rankedAnswer msg $ \srrs _rank -> do
        let arrsigRRs = rrListWith RRSIG (signedA <=< DNS.fromRData) dom (\_ rr -> rr) srrs
        case arrsigRRs of
            [] -> fallback
            _ : _ -> hasDelegation <$> getWorkaround
      where
        {- Case when apex of cohabited child-zone has A record,
           * with DNSSEC, signed with child-zone apex.
           * without DNSSEC, indistinguishable from the A definition without sub-domain cohabitation -}
        signedA rd@RD_RRSIG{..} = guard (rrsig_type == A && rrsig_zone == dom) $> rd
    verificationError = do
        lift . logLn Log.WARN $ "servsChildZone: " ++ show dom ++ ": verification error. invalid SOA:"
        lift . clogLn Log.DEMO (Just Red) $ show dom ++ ": verification error. invalid SOA"
        throwDnsError DNS.ServerFailure
    getWorkaround = fillsDNSSEC nss (Delegation dom (delegationNS nss) (NotFilledDS ServsChildZone) [] (delegationFresh nss))

fillsDNSSEC :: Delegation -> Delegation -> DNSQuery Delegation
fillsDNSSEC nss d = do
    filled@Delegation{..} <- fillDelegationDNSKEY =<< fillDelegationDS nss d
    when (delegationHasDS filled && null delegationDNSKEY) $ do
        let zone = show delegationZone
        lift . logLn Log.WARN $ "fillsDNSSEC: " ++ zone ++ ": DS is not null, and DNSKEY is null"
        lift . clogLn Log.DEMO (Just Red) $ zone ++ ": verification error. dangling DS chain. DS exists, and DNSKEY does not exists"
        throwDnsError DNS.ServerFailure
    return filled

-- | Fill DS for delegation info. The result must be `FilledDS` for success query.
--
-- >>> Right dummyKey = Opaque.fromBase64 "dummykey///dummykey///dummykey///dummykey///"
-- >>> dummyDNSKEY = RD_DNSKEY [ZONE] 3 RSASHA256 $ toPubKey RSASHA256 dummyKey
-- >>> Right dummyDS_ = Opaque.fromBase16 "0123456789ABCD0123456789ABCD0123456789ABCD0123456789ABCD"
-- >>> dummyDS = RD_DS 0 RSASHA256 SHA256 dummyDS_
-- >>> withNS2 dom h1 a1 h2 a2 ds = Delegation dom (DEwithA4 h1 (a1:|[]) :| [DEwithA4 h2 (a2:|[])]) ds [dummyDNSKEY] FreshD
-- >>> parent = withNS2 "org." "a0.org.afilias-nst.info." "199.19.56.1" "a2.org.afilias-nst.info." "199.249.112.1" (FilledDS [dummyDS])
-- >>> mkChild ds = withNS2 "mew.org." "ns1.mew.org." "202.238.220.92" "ns2.mew.org." "210.155.141.200" ds
-- >>> isFilled d = case (delegationDS d) of { NotFilledDS {} -> False; FilledDS {} -> True; FilledRoot -> True }
-- >>> env <- _newTestEnv
-- >>> runChild child = runDNSQuery (fillDelegationDS parent child) env (queryContextIN "ns1.mew.org." A mempty)
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS CachedDelegation)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS ServsChildZone)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ FilledDS [])
-- Right True
fillDelegationDS :: Delegation -> Delegation -> DNSQuery Delegation
fillDelegationDS src dest
    | null $ delegationDNSKEY src = fill [] {- no src DNSKEY, not chained -}
    | NotFilledDS o <- delegationDS src = do
        lift $ logLn Log.WARN $ "fillDelegationDS: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show (delegationZone src)
        return dest
    | FilledDS [] <- delegationDS src = fill [] {- no src DS, not chained -}
    | Delegation{..} <- dest = case delegationDS of
        FilledRoot -> pure dest {- specified root-dnskey case, filled root -}
        FilledDS _ -> pure dest {- no DS or exist DS, anyway filled DS -}
        NotFilledDS o -> do
            lift $ logLn Log.DEMO $ "fillDelegationDS: consumes not-filled DS: case=" ++ show o ++ " zone: " ++ show delegationZone
            maybe (list1 nullIPs query =<< delegationIPs src) (lift . fill . toDSs) =<< lift (lookupValid delegationZone DS)
  where
    toDSs (rrset, _rank) = [rd | rd0 <- rrsRDatas rrset, Just rd <- [DNS.fromRData rd0]]
    fill dss = return dest{delegationDS = FilledDS dss}
    nullIPs = lift $ logLn Log.WARN "fillDelegationDS: ip list is null" *> return dest
    verifyFailed ~es = lift (logLn Log.WARN $ "fillDelegationDS: " ++ es) *> throwDnsError DNS.ServerFailure
    query ips = do
        let zone = delegationZone dest
            result (e, ~verifyColor, ~verifyMsg) = do
                let domTraceMsg = show (delegationZone src) ++ " -> " ++ show zone
                lift . clogLn Log.DEMO (Just verifyColor) $ "fill delegation - " ++ verifyMsg ++ ": " ++ domTraceMsg
                either verifyFailed fill e
        lift $ logLn Log.DEMO . unwords $ ["fillDelegationDS: query", show (zone, DS), "servers:"] ++ [show ip | ip <- ips]
        result =<< queryDS (delegationZone src) (delegationDNSKEY src) ips zone

queryDS
    :: Domain
    -> [RD_DNSKEY]
    -> [IP]
    -> Domain
    -> DNSQuery (Either String [RD_DS], Color, String)
queryDS zone dnskeys ips dom = do
    msg <- norec True ips dom DS
    getSec <- lift $ asks currentSeconds_
    Verify.cases getSec zone dnskeys rankedAnswer msg dom DS (DNS.fromRData . rdata) nullDS ncDS verifyResult
  where
    nullDS = pure (Right [], Yellow, "no DS, so no verify")
    ncDS _ncLog = pure (Left "queryDS: not canonical DS", Red, "not canonical DS")
    verifyResult dsrds dsRRset cacheDS
        | rrsetValid dsRRset = lift cacheDS $> (Right dsrds, Green, "verification success - RRSIG of DS")
        | otherwise = pure (Left "queryDS: verification failed - RRSIG of DS", Red, "verification failed - RRSIG of DS")

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY :: Delegation -> DNSQuery Delegation
fillDelegationDNSKEY d@Delegation{delegationDS = NotFilledDS o, delegationZone = zone} = do
    {- DS(Delegation Signer) is not filled -}
    lift $ logLn Log.WARN $ "fillDelegationDNSKEY: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show zone
    return d
fillDelegationDNSKEY d@Delegation{delegationDS = FilledRoot} = return d {- assume filled in root-priming -}
fillDelegationDNSKEY d@Delegation{delegationDS = FilledDS []} = return d {- DS(Delegation Signer) does not exist -}
fillDelegationDNSKEY d@Delegation{delegationDS = FilledDS (_ : _), delegationDNSKEY = _ : _} = return d
fillDelegationDNSKEY d@Delegation{delegationDS = FilledDS dss@(_ : _), delegationDNSKEY = [], ..} =
    maybe (list1 nullIPs query =<< delegationIPs d) (lift . fill . toDNSKEYs) =<< lift (lookupValid zone DNSKEY)
  where
    zone = delegationZone
    toDNSKEYs (rrset, _rank) = [rd | rd0 <- rrsRDatas rrset, Just rd <- [DNS.fromRData rd0]]
    fill dnskeys = return d{delegationDNSKEY = dnskeys}
    nullIPs = lift $ logLn Log.WARN "fillDelegationDNSKEY: ip list is null" *> return d
    verifyFailed ~es = lift (logLn Log.WARN $ "fillDelegationDNSKEY: " ++ es) *> return d
    query ips = do
        lift $ logLn Log.DEMO . unwords $ ["fillDelegationDNSKEY: query", show (zone, DNSKEY), "servers:"] ++ [show ip | ip <- ips]
        either verifyFailed (lift . fill) =<< cachedDNSKEY dss ips zone
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- Get authoritative server addresses from the delegation information.
delegationIPs :: Delegation -> DNSQuery [IP]
delegationIPs Delegation{..} = do
    disableV6NS <- lift (asks disableV6NS_)
    ips <- dentryToRandomIP entryNum addrNum disableV6NS dentry
    when (null ips) $ throwDnsError DNS.UnknownDNSError  {- assume filled IPs by fillDelegation -}
    pure ips
  where
    dentry = NE.toList delegationNS
    entryNum = 2
    addrNum = 2
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
-- If Nothing, it is a miss-hit against the cache.
-- If Just NoDelegation, cache hit but no delegation information.
lookupDelegation :: Domain -> ContextT IO (Maybe MayDelegation)
lookupDelegation zone = do
    disableV6NS <- asks disableV6NS_
    let noCachedV4NS es = disableV6NS && all noV4DEntry es

        fromDEs es
            {- all NS records for A are skipped under disableV6NS, so handle as miss-hit NS case -}
            | noCachedV4NS es = Nothing
            --
            {- Nothing case, all NS records are skipped, so handle as miss-hit NS case -}
            | otherwise = list Nothing ((Just .) . hasDelegation') es
          where hasDelegation' de des = hasDelegation $ Delegation zone (de :| des) (NotFilledDS CachedDelegation) [] CachedD

        getDelegation :: ([ResourceRecord], a) -> ContextT IO (Maybe MayDelegation)
        getDelegation (rrs, _) = do
            {- NS cache hit -}
            let nss = sort $ nsList zone const rrs
            case nss of
                []     -> return $ Just noDelegation {- hit null NS list, so no delegation -}
                _ : _  -> fromDEs . concat <$> mapM (lookupDEntry zone) nss

    maybe (return Nothing) getDelegation =<< lookupCache zone NS
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
noV4DEntry :: DEntry -> Bool
noV4DEntry (DEonlyNS {})          = True
noV4DEntry (DEwithA4 _ (_:|_))    = False
noV4DEntry (DEwithA6 _ _)         = True
noV4DEntry (DEwithAx _ (_:|_) _)  = False
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- Caching while retrieving delegation information from the authoritative server's reply
delegationWithCache :: Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> DNSQuery MayDelegation
delegationWithCache zone dnskeys dom msg = do
    {- There is delegation information only when there is a selectable NS -}
    getSec <- lift $ asks currentSeconds_
    maybe (notFound $> noDelegation) (found getSec >>> (<&> hasDelegation)) $ findDelegation nsps adds
  where
    found getSec k = Verify.cases getSec zone dnskeys rankedAuthority msg dom DS fromDS (nullDS k) ncDS (withDS k)
    fromDS = DNS.fromRData . rdata
    {- TODO: NoData DS negative cache -}
    nullDS k = do
        unsignedDelegationOrNoData $> ()
        lift $ vrfyLog (Just Yellow) "delegation - no DS, so no verification chain"
        lift $ caches $> k []
    ncDS _ncLog = lift (vrfyLog (Just Red) "delegation - not canonical DS") *> throwDnsError DNS.ServerFailure
    withDS k dsrds dsRRset cacheDS
        | rrsetValid dsRRset = lift $ do
            let x = k dsrds
            vrfyLog (Just Green) "delegation - verification success - RRSIG of DS"
            caches *> cacheDS $> x
        | otherwise =
            lift (vrfyLog (Just Red) "delegation - verification failed - RRSIG of DS") *> throwDnsError DNS.ServerFailure
    caches = cacheNS *> cacheAdds

    notFound = lift $ vrfyLog Nothing "no delegation"
    vrfyLog vrfyColor vrfyMsg = clogLn Log.DEMO vrfyColor $ vrfyMsg ++ ": " ++ domTraceMsg
    domTraceMsg = show zone ++ " -> " ++ show dom

    (nsps, cacheNS) = withSection rankedAuthority msg $ \rrs rank ->
        let nsps_ = nsList dom (,) rrs in (nsps_, cacheNoRRSIG (map snd nsps_) rank)

    (adds, cacheAdds) = withSection rankedAdditional msg $ \rrs rank ->
        let axs = filter match rrs in (axs, cacheSection axs rank)
      where
        match rr = rrtype rr `elem` [A, AAAA] && rrname rr `isSubDomainOf` zone && rrname rr `Set.member` nsSet
        nsSet = Set.fromList $ map fst nsps

    unsignedDelegationOrNoData = unsignedDelegationOrNoDataAction zone dnskeys dom A msg
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fillCachedDelegation :: Delegation -> DNSQuery Delegation
fillCachedDelegation d = list noAvail result =<< lift (concat <$> mapM fill des)
  where
    des = delegationNS d
    fill (DEonlyNS ns) = lookupDEntry (delegationZone d) ns
    fill  e            = pure [e]
    noAvail = lift (logLines Log.DEMO ("fillCachedDelegation - no NS available: " : pprNS des)) *> throwDnsError DNS.ServerFailure
    pprNS (e:|es) = map (("  " ++) . show) $ e : es
    result e es = pure $ d{delegationNS = e :| es}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
lookupDEntry :: Domain -> Domain -> ContextT IO [DEntry]
lookupDEntry zone ns = do
    withNX =<< lookupCache ns Cache.NX
  where
    withNX Just{}   = pure []
    withNX Nothing  = do
        let takeV4 = rrListWith A    (`DNS.rdataField` DNS.a_ipv4)    ns const
            takeV6 = rrListWith AAAA (`DNS.rdataField` DNS.aaaa_ipv6) ns const
        lk4 <- fmap (takeV4 . fst) <$> lookupCache ns A
        lk6 <- fmap (takeV6 . fst) <$> lookupCache ns AAAA
        pure $ dentryFromCache zone ns lk4 lk6
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- | result value cases of dentryFromCache :
--     []             : miss-hit, skip this NS name, to avoid iterative loop
--     [DEonlyNS {}]  : miss-hit
--     [DEwithA...]   : hit
--
-- >>> :seti -XOverloadedStrings
-- >>> dentryFromCache "example." "ns.example." Nothing Nothing
-- []
-- >>> dentryFromCache "example." "ns.example." Nothing (Just [])
-- []
-- >>> dentryFromCache "example." "ns.example." (Just []) Nothing
-- []
-- >>> dentryFromCache "example." "ns.example." (Just []) (Just [])
-- []
-- >>> dentryFromCache "a.example." "ns.example." Nothing Nothing
-- [DEonlyNS "ns.example."]
-- >>> dentryFromCache "a.example." "ns.example." Nothing (Just [])
-- [DEonlyNS "ns.example."]
-- >>> dentryFromCache "a.example." "ns.example." (Just []) Nothing
-- [DEonlyNS "ns.example."]
-- >>> dentryFromCache "a.example." "ns.example." (Just []) (Just [])
-- []
-- >>> dentryFromCache "a.example." "ns.example." (Just ["192.0.2.1"]) (Just [])
-- [DEwithA4 "ns.example." (192.0.2.1 :| [])]
-- >>> dentryFromCache "a.example." "ns.example." (Just []) (Just ["2001:db8::1"])
-- [DEwithA6 "ns.example." (2001:db8::1 :| [])]
-- >>> dentryFromCache "a.example." "ns.example." (Just ["192.0.2.1"]) (Just ["2001:db8::1"])
-- [DEwithAx "ns.example." (192.0.2.1 :| []) (2001:db8::1 :| [])]
dentryFromCache :: Domain -> Domain -> Maybe [IPv4] -> Maybe [IPv6] -> [DEntry]
dentryFromCache zone ns = dispatch
  where
    missHit
        | ns `DNS.isSubDomainOf` zone  = []  {- miss-hit with sub-domain case cause iterative loop. null result to skip this NS -}
        | otherwise                    = [DEonlyNS ns]
    dispatch Nothing       Nothing          = missHit  {- A: miss-hit     AAAA: miss-hit                       -}
    dispatch Nothing       (Just [])        = missHit  {- A: miss-hit     AAAA: hit NoData  , assumes miss-hit -}
    dispatch (Just [])     Nothing          = missHit  {- A: hit NoData   AAAA: miss-hit    , assumes miss-hit -}
    dispatch Nothing       (Just (i:is))    = [DEwithA6 ns (i :| is)]
    dispatch (Just (i:is)) Nothing          = [DEwithA4 ns (i :| is)]
    dispatch (Just i4s)   (Just i6s)        = foldIPList'
                                              []       {- A: hit NoData   AAAA: hit NoData  , maybe wrong cache, skip this NS -}
                                              (\v4    -> [DEwithA4 ns v4])
                                              (\v6    -> [DEwithA6 ns v6])
                                              (\v4 v6 -> [DEwithAx ns v4 v6])
                                              i4s i6s
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
unsignedDelegationOrNoDataAction
    :: Domain -> [RD_DNSKEY]
    -> Domain -> TYPE -> DNSMessage
    -> DNSQuery [RRset]
unsignedDelegationOrNoDataAction zone dnskeys qname_ qtype_ msg = join $ lift nsec
  where
    nsec  = Verify.nsecWithValid   dnskeys rankedAuthority msg nullNSEC invalidK nsecK
    nullNSEC = nsec3
    nsecK  ranges rrsets doCache =
        Verify.runHandlers "cannot handle NSEC UnsignedDelegation/NoDatas:"  noWitnessK $
        handle unsignedDelegation resultK .
        handle wildcardNoData     resultK .
        handle noData             resultK
      where
        handle = Verify.mkHandler ranges rrsets doCache
        unsignedDelegation rs  = SEC.unsignedDelegationNSEC   zone rs qname_
        wildcardNoData     rs  = SEC.wildcardNoDataNSEC       zone rs qname_ qtype_
        noData             rs  = SEC.noDataNSEC               zone rs qname_ qtype_

    nsec3 = Verify.nsec3WithValid  dnskeys rankedAuthority msg nullK    invalidK nsec3K
    nsec3K ranges rrsets doCache =
        Verify.runHandlers "cannot handle NSEC3 UnsignedDelegation/NoDatas:" noWitnessK $
        handle unsignedDelegation resultK .
        handle wildcardNoData     resultK .
        handle noData             resultK
      where
        handle = Verify.mkHandler ranges rrsets doCache
        unsignedDelegation rs  = SEC.unsignedDelegationNSEC3  zone rs qname_
        wildcardNoData     rs  = SEC.wildcardNoDataNSEC3      zone rs qname_ qtype_
        noData             rs  = SEC.noDataNSEC3              zone rs qname_ qtype_

    nullK = pure $ noverify "no NSEC/NSEC3 records" $> []
    invalidK s = failed $ "invalid NSEC/NSEC3: " ++ traceInfo ++ " : " ++ s
    noWitnessK s = pure $ noverify ("nsec witness not found: " ++ traceInfo ++ " : " ++ s) $> []
    resultK w rrsets _ = pure $ success w $> rrsets

    success w = putLog (Just Green) $ "nsec verification success - " ++ witnessInfo w
    noverify s = putLog (Just Yellow) $ "nsec no verification - " ++ s
    failed s = pure $ putLog (Just Red) ( "nsec verification failed - " ++ s) *> throwDnsError DNS.ServerFailure

    putLog color s = lift $ clogLn Log.DEMO color s

    witnessInfo w = SEC.witnessName w ++ ": " ++ SEC.witnessDelegation w traceInfo qinfo
    traceInfo = show zone ++ " -> " ++ show qname_
    qinfo = show qname_ ++ " " ++ show qtype_
{- FOURMOLU_ENABLE -}
