{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Iterative.Query.Resolve (
    resolveByCache64,
    resolve64,
    runResolve,
    resolveByCache,
    resolve,
) where

-- GHC packages
import Control.Monad.Trans.Maybe hiding (liftCallCC, liftCatch, liftListen, liftPass)

-- dnsext-types
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IPv4, IPv6, fromIPv4, toIPv6b)

-- dnsext-utils
import qualified DNS.Log as Log
import DNS.RRCache (Ranking (RankAdditional))
import qualified DNS.RRCache as Cache
import DNS.WorkerStats (noopWorkerStat)

-- dnsext-do53
import DNS.Do53.Client (QueryControls (..))

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Class
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.ResolveJust
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils


{- FOURMOLU_DISABLE -}
resolveByCache64 :: MonadContext m => Question -> m (([RRset], Domain), Maybe ResultRRS)
resolveByCache64 = withDNS64aaaa resolveByCache h
  where
    h action x1 = case x1 of
        (_,  Nothing)   ->  result64  {- case, AAAA mis-hit -}
        (_, Just res) ->  aaaaNoData id res
                            not64     {- case, AAAA exist cached -}
                            result64  {- case, AAAA NoData cached -}
      where
        not64 = return x1
        result64 = action <&> \x2 -> fmap dns64Result <$> x2

{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
resolve64 :: MonadQuery m => Question -> m (([RRset], Domain), Either ResultRRS (ResultRRS' DNSMessage))
resolve64 = withDNS64aaaa resolve h
  where
    h action x1 = case x1 of
        (_, Left res)  -> aaaaNoData id res
                            not64     {- case, AAAA exist cached -}
                            result64  {- case, AAAA NoData cached -}

        (_, Right res) -> aaaaNoData rcode res
                            not64     {- case, AAAA exist -}
                            result64  {- case, AAAA NoData  -}
      where
        not64 = return x1
        result64 = action <&> h2
    h2 (cn, Left  rs)  = (cn, Left (dns64Result rs))
    h2 (cn, Right rs)  = (cn, Right (dns64Result rs))
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
withDNS64aaaa
    :: Monad m
    => (Question -> m a)
    -> (m a -> a -> m a) -> Question -> m a
withDNS64aaaa action k q@Question{ qtype = AAAA }  = action q >>= k (action q{ qtype = A })
withDNS64aaaa action _ q@Question{}                = action q
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
aaaaNoData :: (a -> RCODE) -> ResultRRS' a -> b -> b -> b
aaaaNoData rc (x, arrs, _orrs) other nodata
    | rc x == NoErr && null rrsV6  = nodata
    | otherwise                    = other
  where
    rrsV6 =
        [ ipv6
        | RRset{ rrsType = AAAA,  rrsRDatas = rds } <- arrs
        , rd <- rds
        , Just ipv6 <- [rdataField rd aaaa_ipv6]
        ]
{- FOURMOLU_ENABLE -}

dns64Result :: ResultRRS' a -> ResultRRS' a
dns64Result (r, arrs, orrs) = (r, map dns64RRset arrs, orrs)

{- FOURMOLU_DISABLE -}
dns64RRset :: RRset -> RRset
dns64RRset rs@RRset{ rrsType = A }  =
    rs{rrsType = AAAA, rrsRDatas = rds' }
  where
    rds' = [ rd_aaaa (dns64IPv6 ipv4)
           | rd <- rrsRDatas rs, Just ipv4 <- [rdataField rd a_ipv4] ]
dns64RRset rs@RRset{ }              = rs
{- FOURMOLU_ENABLE -}

dns64IPv6 :: IPv4 -> IPv6
dns64IPv6 ipv4 = toIPv6b [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, i1, i2, i3, i4]
  where
    [i1, i2, i3, i4] = fromIPv4 ipv4

-- | Getting the final result.
runResolve
    :: Env
    -> Question
    -> QueryControls
    -> IO (Either QueryError (([RRset], Domain), Either ResultRRS (ResultRRS' DNSMessage)))
runResolve cxt q qctl = runDNSQuery (resolve q) cxt noopWorkerStat $ queryParam q qctl

resolveByCache :: MonadContext m => Question -> m (([RRset], Domain), Maybe ResultRRS)
resolveByCache = resolveLogic "cache" Just (const Nothing) (\_ -> pure ((), [], [])) (\_ _ -> pure $ Right ((), [], []))

-- |
-- Use iterative resolution to obtain the final `DNSMessage` from the authoritative server.
-- If a cached entry with a rank of `RankAnswer` or higher for the target `TYPE` is found, it is returned as the result.
-- If the target `TYPE` is not `CNAME` and the result is a `CNAME`, resolution is repeated.
-- During this process, the `CNAME` record is written to the cache.
-- The resulting record for the target `TYPE` is also cached.
resolve :: MonadQuery m => Question -> m (([RRset], Domain), Either ResultRRS (ResultRRS' DNSMessage))
resolve = resolveLogic "query" Left Right resolveCNAME resolveTYPE

{- FOURMOLU_DISABLE -}
-- result value of resolveLogic:
--   * left   :: ResultRRS -> b       - cached result
--   * right  :: ResultRRS' a -> b    - queried result like (ResultRRS' DNSMessage)
resolveLogic
    :: MonadContext m
    => String
    -> (ResultRRS -> b) -> (ResultRRS' a -> b)
    -> (Domain -> m (ResultRRS' a))
    -> (Domain -> TYPE -> m (Either (Domain, RRset) (ResultRRS' a)))
    -> Question
    -> m (([RRset], Domain), b)
resolveLogic logMark left right cnameHandler typeHandler (Question n0 typ cls) =
    called >> notLocal
  where
    notLocal
        | cls /= IN        = pure (([], n0), left (DNS.NoErr, [], []))  {- not support other than IN -}
        | typ == Cache.ERR = pure (([], n0), left (DNS.NoErr, [], []))
        | typ == ANY       = pure (([], n0), left (DNS.NotImpl, [], []))
        | typ == CNAME     = justCNAME n0
        | otherwise        = recCNAMEs 0 n0 id
    logLines__ lv = logLines lv . pindents ("resolve: " ++ logMark)
    logLn_ lv s = logLines__ lv [s]
    called = do
        let qbitstr tag sel tbl = ((tag ++ ":") ++) . fromMaybe "" . (`lookup` tbl) <$> asksQP sel
        do_ <- qbitstr "DnssecOK"           requestDO_  [(DnssecOK,           "1"), (NoDnssecOK,           "0")]
        cd_ <- qbitstr "CheckDisabled"      requestCD_  [(CheckDisabled,      "1"), (NoCheckDisabled,      "0")]
        ad_ <- qbitstr "AuthenticatedData"  requestAD_  [(AuthenticatedData,  "1"), (NoAuthenticatedData,  "0")]
        logLines__ Log.DEMO [unwords [show n0, show typ, show cls], intercalate ", " [do_, cd_, ad_]]
    justCNAME bn = withNegativeTrustAnchor bn $ do
        let result x = (([], bn), x)

            errorCached = MaybeT (lookupERR bn) <&> \(rc, soa) -> result $ left (rc, [], soa)
            cnameCached = result . left . foldLookupResult negative noSOA positive <$> MaybeT (lookupType bn CNAME)
              where
                negative soa nsecs _rank  = (DNS.NoErr, [], soa : nsecs)
                noSOA rc                  = (rc, [], [])
                positive cname            = (DNS.NoErr, [cname], [])

        (maybe (result . right <$> cnameHandler bn) pure =<<) $ runMaybeT $
            cnameCached <|> errorCached

    -- For queries of types other than `CNAME`, perform a new lookup using the label from the `CNAME` record.
    -- recCNAMEs :: Int -> Domain -> [RRset] -> DNSQuery (([RRset], Domain), Either Result a)
    recCNAMEs cc bn dcnRRsets
        | cc > mcc = do
            logLn_ Log.WARN $ "cname chain limit exceeded: " ++ show (n0, typ)
            failWithCacheOrigName Cache.RankAnswer ServerFailure
        | otherwise = withNegativeTrustAnchor bn $ do
            let traceCNAME cn = logLn_ Log.DEMO ("cname: " ++ show bn ++ " -> " ++ show cn)
                recCNAMEs_ (cn, cnRRset) = traceCNAME cn *> recCNAMEs (succ cc) cn (dcnRRsets . (cnRRset :))

                result x = ((dcnRRsets [], bn), x)

                notCached = either recCNAMEs_ (pure . result . right)
                typeCached = result . left . foldLookupResult negative noSOA positive <$> MaybeT (lookupType bn typ)
                  where
                    negative soa nsecs _rank  = (DNS.NoErr, [], soa : nsecs)
                    noSOA rc                  = (rc, [], [])
                    positive xrrs             = (DNS.NoErr, [xrrs], [])  {- cached result with target typ -}
                lookupCNAME = MaybeT $ (withCN =<<) . (foldLK =<<) <$> lookupType bn CNAME
                  where
                    foldLK = foldLookupResult (\_ _ _ -> Nothing) (\_ -> Nothing) Just
                    withCN cnRRset = uncons cns <&> \(cn, _) -> (cn, cnRRset)
                      where
                        cns = [cn | rd <- rrsRDatas cnRRset, Just cn <- [DNS.rdataField rd DNS.cname_domain]]
                errorCached = MaybeT (lookupERR bn) <&> \(rc, soa) -> result $ left (rc, [], soa)

            (maybe (notCached =<< typeHandler bn typ) pure =<<) $ runMaybeT $
                typeCached                           <|>
                (lift . recCNAMEs_ =<<) lookupCNAME  <|>
                errorCached
      where
        mcc = maxCNameChain

    lookupERR name =
        maybe (pure Nothing) (foldLookupResult soah (\rc -> pure $ Just (rc, [])) inconsistent)
            =<< lookupType name Cache.ERR
      where
        {- authority section is cached as RankAdditional, so not applying guardReply -}
        soah soa nsecs _rank = pure $ Just (NXDomain, soa : nsecs)
        inconsistent rrs = do
            logLn_ Log.WARN $ "inconsistent ERR cache found: dom=" ++ show name ++ ", " ++ show rrs
            return Nothing

    lookupType bn t = maybe (pure empty) filterLookup =<< lookupRRsetEither logMark bn t
    filterLookup (x, rank) = do
        reqCD <- asksQP requestCD_
        pure $ do
            guardReply rank
            guardLookup reqCD x
            Just x
    --
    guardLookup reqCD = foldLookupResult (guardNegative reqCD) (guardNegativeNoSOA reqCD) (guardPositive reqCD)
    {- {- authority section is cached as RankAdditional, so not applying guard -} guardReply soaRank *> -}
    guardNegative reqCD soa _nsecs _soaRank = guardMayVerified reqCD soa
    guardNegativeNoSOA CheckDisabled   _rc = empty    {- query again for verification error -}
    guardNegativeNoSOA NoCheckDisabled _rc = pure ()
    guardPositive reqCD rrset = guardMayVerified reqCD rrset
    --
    guardMayVerified reqCD rrset = mayVerifiedRRS (pure ()) guardCD (\_ -> empty) (\_ -> pure ()) $ rrsMayVerified rrset
      where guardCD = guardAllowCachedCD reqCD
    guardAllowCachedCD CheckDisabled    = pure ()
    guardAllowCachedCD NoCheckDisabled  = empty
    -- the lowest ranking is not used for the reply's answer.
    -- + https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1
    guardReply rank = guard (rank > RankAdditional)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- retrieve and cache the `CNAME` record
resolveCNAME :: MonadQuery m => Domain -> m (ResultRRS' DNSMessage)
resolveCNAME bn = do
    (msg, d) <- resolveExact bn CNAME
    uncurry ((,,) msg) <$> cacheAnswer d bn CNAME msg
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- If a record of the desired `TYPE` is successfully retrieved, return the resulting `DNSMessage` and RRset.
-- If the result is a `CNAME`, return the domain name and RRset.
-- In both case, cache the resulting record.
--
-- returns: result msg, cname, verified answer, verified authority
resolveTYPE :: MonadQuery m => Domain -> TYPE -> m (Either (Domain, RRset) (ResultRRS' DNSMessage))
resolveTYPE bn typ = do
    (msg, delegation) <- resolveExact bn typ
    let has ty = any ((&&) <$> (== bn) . rrname <*> (== ty) . rrtype) $ DNS.answer msg
        hasCNAME  = has CNAME
        cns cnAns = [(cn, cnRRset) | cnRRset <- cnAns, rd <- rrsRDatas cnRRset, Just cn <- [DNS.rdataField rd DNS.cname_domain]]
        ierr = logLn Log.WARN (pprMessage "resolveTYPE: inconsistent, cnames exists or not" msg) >> throwDnsError ServerFailure
        cnResult (cnAns, _cnAuth) = list ierr (\cn _ -> pure $ Left cn) $ cns cnAns
        dispatch
            | not hasCNAME                   = Right . uncurry ((,,) msg) <$> cacheAnswer delegation bn typ msg
            |     hasCNAME && not (has typ)  = cnResult =<< cacheAnswer delegation bn CNAME msg
            | otherwise                      = throwDnsError UnexpectedRDATA {- If both CNAME and the target RR exist, it results in an error. -}
    dispatch
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
withNegativeTrustAnchor :: MonadContext m => Domain -> m a -> m a
withNegativeTrustAnchor qn action = do
   let cases _       CheckDisabled    = CheckDisabled
       cases Just{}  NoCheckDisabled  = CheckDisabled  {- negative-trust-anchor found -}
       cases Nothing NoCheckDisabled  = NoCheckDisabled
       getModify nta qp = qp{requestCD_ = cases nta (requestCD_ qp)}
   modify <- getModify <$> findNegativeTrustAnchor qn
   localQP modify action
{- FOURMOLU_ENABLE -}

maxCNameChain :: Int
maxCNameChain = 16
