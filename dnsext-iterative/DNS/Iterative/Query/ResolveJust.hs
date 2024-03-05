{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.ResolveJust (
    -- * Iteratively search authritative server and exactly query to that
    runResolveExact,
    resolveExact,
    runIterative,

    -- * backword compatibility
    runResolveJust,
    resolveJust,
) where

-- GHC packages
import qualified Data.List.NonEmpty as NE

-- other packages

-- dnsext packages
import DNS.Do53.Client (QueryControls (..))
import qualified DNS.Log as Log
import DNS.RRCache (
    rankedAnswer,
 )
import qualified DNS.RRCache as Cache
import DNS.SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Delegation
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Norec
import DNS.Iterative.Query.Random
import DNS.Iterative.Query.Root
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils

---- import for doctest
import DNS.Iterative.Query.TestEnv

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> import System.IO
-- >>> import DNS.SEC
-- >>> DNS.runInitIO addResourceDataForDNSSEC
-- >>> hSetBuffering stdout LineBuffering

-- test env use from doctest
_newTestEnv :: IO Env
_newTestEnv = newTestEnvNoCache findConsumed True
  where
    findConsumed ss
        | any ("consumes not-filled DS:" `isInfixOf`) ss = putStrLn "consume message found"
        | otherwise = pure ()

---

{-# DEPRECATED runResolveJust "use resolveExact instead of this" #-}
runResolveJust
    :: Env
    -> Domain
    -> TYPE
    -> QueryControls
    -> IO (Either QueryError (DNSMessage, Delegation))
runResolveJust = runResolveExact

-- 権威サーバーからの解決結果を得る
runResolveExact
    :: Env
    -> Domain
    -> TYPE
    -> QueryControls
    -> IO (Either QueryError (DNSMessage, Delegation))
runResolveExact cxt n typ cd = runDNSQuery (resolveExact n typ) cxt $ queryContextIN n typ cd

{-# DEPRECATED resolveJust "use resolveExact instead of this" #-}
resolveJust :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJust = resolveExact

-- 反復検索を使って最終的な権威サーバーからの DNSMessage とその委任情報を得る. CNAME は解決しない.
resolveExact :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveExact = resolveExactDC 0

resolveExactDC :: Int -> Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveExactDC dc n typ
    | dc > mdc = do
        lift . logLn Log.WARN $ "resolve-exact: not sub-level delegation limit exceeded: " ++ show (n, typ)
        failWithCacheOrigQ Cache.RankAnswer DNS.ServerFailure
    | otherwise = do
        root <- refreshRoot
        nss@Delegation{..} <- iterative_ dc root $ DNS.superDomains n
        sas <- delegationIPs nss
        lift . logLn Log.DEMO $ unwords (["resolve-exact: query", show (n, typ), "servers:"] ++ [show sa | sa <- sas])
        let dnssecOK = delegationHasDS nss && not (null delegationDNSKEY)
        (,) <$> norec dnssecOK sas n typ <*> pure nss
  where
    mdc = maxNotSublevelDelegation

maxNotSublevelDelegation :: Int
maxNotSublevelDelegation = 16

-- 反復後の委任情報を得る
runIterative
    :: Env
    -> Delegation
    -> Domain
    -> QueryControls
    -> IO (Either QueryError Delegation)
runIterative cxt sa n cd = runDNSQuery (iterative sa n) cxt $ queryContextIN n A cd

-- | 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威サーバー群を見つける
--
-- >>> testIterative dom = do { root <- refreshRoot; iterative root dom }
-- >>> env <- _newTestEnv
-- >>> runDNSQuery (testIterative "mew.org.") env (queryContextIN "mew.org." A mempty) $> ()  {- fill-action is not called -}
--
-- >>> runDNSQuery (testIterative "arpa.") env (queryContextIN "arpa." NS mempty) $> ()  {- fill-action is called for `ServsChildZone` -}
-- consume message found
iterative :: Delegation -> Domain -> DNSQuery Delegation
iterative sa n = iterative_ 0 sa $ DNS.superDomains n

{- FOURMOLU_DISABLE -}
iterative_ :: Int -> Delegation -> [Domain] -> DNSQuery Delegation
iterative_ _ nss0 [] = return nss0
iterative_ dc nss0 (x : xs) =
    {- If NS is not returned, the information of the same NS is used for the child domain. or.jp and ad.jp are examples of this case. -}
    step nss0 >>= mayDelegation (recurse nss0 xs) (`recurse` xs)
  where
    recurse = iterative_ dc {- sub-level delegation. increase dc only not sub-level case. -}
    name = x

    lookupNX :: ContextT IO Bool
    lookupNX = isJust <$> lookupCache name Cache.NX

    stepQuery :: Delegation -> DNSQuery MayDelegation
    stepQuery nss@Delegation{..} = do
        let zone = delegationZone
            dnskeys = delegationDNSKEY
        {- When the same NS information is inherited from the parent domain, balancing is performed by re-selecting the NS address. -}
        sas <- delegationIPs nss
        lift . logLn Log.DEMO $ unwords (["iterative: query", show (name, A), "servers:"] ++ [show sa | sa <- sas])
        let dnssecOK = delegationHasDS nss && not (null delegationDNSKEY)
        {- Use `A` for iterative queries to the authoritative servers during iterative resolution.
           See the following document:
           QNAME Minimisation Examples: https://datatracker.ietf.org/doc/html/rfc9156#section-4 -}
        msg <- norec dnssecOK sas name A
        let withNoDelegation handler = mayDelegation handler (return . hasDelegation)
            sharedHandler = servsChildZone nss name msg
            cacheHandler = cacheNoDelegation nss zone dnskeys name msg $> noDelegation
            logFound d = lift (logDelegation d) $> d
        delegationWithCache zone dnskeys name msg
            >>= withNoDelegation sharedHandler
            >>= withNoDelegation cacheHandler
            >>= mapM fillCachedDelegation {- fill from cache for fresh NS list -}
            >>= mapM logFound
    logDelegation Delegation{..} = do
        let zplogLn lv = logLn lv . (("zone: " ++ show delegationZone ++ ":\n") ++)
        putDelegation PPFull delegationNS (zplogLn Log.DEMO) (zplogLn Log.DEBUG)

    step :: Delegation -> DNSQuery MayDelegation
    step nss@Delegation{..} = do
        let withNXC nxc
                | nxc = pure noDelegation
                | otherwise = stepQuery nss
            getDelegation FreshD = stepQuery nss {- refresh for fresh parent -}
            getDelegation CachedD = lift (lookupDelegation name) >>= maybe (lift lookupNX >>= withNXC) pure
        getDelegation delegationFresh >>= mapM (fillDelegation dc) >>= mapM (fillsDNSSEC nss)
        --                                {- fill for no address cases -}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fillDelegation :: Int -> Delegation -> DNSQuery Delegation
fillDelegation dc d0 = do
    disableV6NS <- lift (asks disableV6NS_)
    fillCachedDelegation =<< fillDelegationOnNull dc disableV6NS d0
    {- lookup again for updated cache with resolveNS -}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- Fill delegation with resolved IPs
-- If no available NS is found, ServerFailure is returned.
fillDelegationOnNull :: Int -> Bool -> Delegation -> DNSQuery Delegation
fillDelegationOnNull dc disableV6NS d0@Delegation{..}
    | dentryIPnull disableV6NS dentry  = case nonEmpty names of
        Nothing      -> do
            Question qn qty _ <- lift (lift $ asks origQuestion_)
            lift $ logLines Log.DEMO
                [ "fillDelegationOnNullIP: serv-fail: delegation is empty."
                , "  zone: " ++ show zone
                , "  orig-query: " ++ show qn ++ " " ++ show qty
                , "  disable-v6-ns: " ++ show disableV6NS
                , "  without-glue sub-domains:" ++ show subNames
                ]
            throwDnsError DNS.ServerFailure
        Just names1  -> do
            name <- randomizedSelectN names1
            (ip, _) <- resolveNS zone disableV6NS dc name
            let filled = case ip of
                    IPv4 v4 -> DEwithA4 name (v4 :| [])
                    IPv6 v6 -> DEwithA6 name (v6 :| [])
            pure $ d0{delegationNS = replaceTo name filled delegationNS}
    | otherwise       = pure d0
  where
    zone = delegationZone
    dentry = NE.toList delegationNS

    names = foldr takeNames [] delegationNS
    takeNames (DEonlyNS name) xs
        | not (name `DNS.isSubDomainOf` zone)  = name : xs
    --    {- skip sub-domain without glue to avoid loop -}
    takeNames  _              xs               =        xs

    replaceTo n alt des = NE.map replace des
      where
        replace (DEonlyNS name)
            | name == n     = alt
        replace  de         = de

    subNames = foldr takeSubNames [] delegationNS
    takeSubNames (DEonlyNS name) xs
        | name `DNS.isSubDomainOf` zone  = name : xs {- sub-domain name without glue -}
    takeSubNames _ xs                    =        xs
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
resolveNS :: Domain -> Bool -> Int -> Domain -> DNSQuery (IP, ResourceRecord)
resolveNS zone disableV6NS dc ns = do
    (axs, rank) <- query1Ax
    maybe (failEmptyAx rank) pure =<< randomizedSelect axs
  where
    axPairs = axList disableV6NS (== ns) (,)

    query1Ax
        | disableV6NS = querySection A
        | otherwise = join $ randomizedChoice q46 q64
      where
        q46 = A +!? AAAA
        q64 = AAAA +!? A
        tx +!? ty = do
            x@(xs, _rank) <- querySection tx
            if null xs then querySection ty else pure x
        querySection typ = do
            lift . logLn Log.DEMO $ unwords ["resolveNS:", show (ns, typ), "dc:" ++ show dc, "->", show (succ dc)]
            {- resolve for not sub-level delegation. increase dc (delegation count) -}
            cacheAnswerAx typ =<< resolveExactDC (succ dc) ns typ
        cacheAnswerAx typ (msg, d) = do
            cacheAnswer d ns typ msg $> ()
            pure $ withSection rankedAnswer msg $ \rrs rank -> (axPairs rrs, rank)

    failEmptyAx rank = do
        let emptyInfo
                | disableV6NS  = "empty A: disable-v6ns: "
                | otherwise    = "empty A|AAAA: "
            showOrig (Question name ty _) = "orig-query " ++ show name ++ " " ++ show ty
        orig <- showOrig <$> lift (lift $ asks origQuestion_)
        lift . logLn Log.WARN $
            "resolveNS: serv-fail, "
            ++ emptyInfo
            ++ orig
            ++ ", zone: "
            ++ show zone
            ++ " NS: "
            ++ show ns
        failWithCacheOrigQ rank DNS.ServerFailure
{- FOURMOLU_ENABLE -}
