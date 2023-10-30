{-# LANGUAGE RecordWildCards #-}

module QuerySpec where

import Test.Hspec

import Control.Concurrent (forkIO, threadDelay)
import Control.Monad (void)
import qualified DNS.RRCache as Cache
import qualified DNS.SEC as DNS
import DNS.Types (TYPE (A, AAAA, CNAME, MX, NS, PTR, SOA))
import qualified DNS.Types as DNS
import Data.Either (isRight)
import Data.Maybe (isJust, isNothing)
import Data.String (fromString)
import System.Environment (lookupEnv)

import qualified DNS.Log as Log

import DNS.Iterative.Internal (
    Delegation (..),
    Env (..),
    getResultIterative,
    newEnv,
    refreshRoot,
    replyMessage,
    rootHint,
    rootPriming,
    rrsetValid,
    runDNSQuery,
    runIterative,
    runResolve,
    runResolveExact,
 )
import DNS.TimeCache (TimeCache (..), newTimeCache)

data AnswerResult
    = Empty DNS.RCODE
    | NotEmpty DNS.RCODE
    | Failed
    deriving (Eq, Show)

data VerifyResult
    = Verified
    | NotVerified
    deriving (Eq, Show)

data VAnswerResult
    = VEmpty DNS.RCODE
    | VNotEmpty DNS.RCODE VerifyResult
    | VFailed
    deriving (Eq, Show)

spec :: Spec
spec = do
    let getEnvBool n = runIO $ maybe False ((== "1") . take 1) <$> lookupEnv n
    disableV6NS <- getEnvBool "DISABLE_V6_NS"
    debug <- getEnvBool "QTEST_DEBUG"
    runIO $ DNS.runInitIO DNS.addResourceDataForDNSSEC
    let debugLog = do
            (logger, putLines, flush) <- Log.new Log.Stdout Log.DEBUG
            void $ forkIO logger -- fixme
            pure (\lv c xs -> putLines lv c [show lv ++ ": " ++ x | x <- xs], flush)
        quiet = (\_ _ _ -> pure (), pure ())
    (putLines, flush) <- if debug then runIO debugLog else pure quiet
    envSpec
    cacheStateSpec disableV6NS putLines
    querySpec disableV6NS putLines
    runIO flush

envSpec :: Spec
envSpec = describe "env" $ do
    it "rootHint" $ do
        let sp p = case p of Delegation{} -> True -- check not error
        rootHint `shouldSatisfy` sp

cacheStateSpec :: Bool -> Log.PutLines -> Spec
cacheStateSpec disableV6NS putLines = describe "cache-state" $ do
    tcache@TimeCache{..} <- runIO newTimeCache
    let cacheConf = Cache.getDefaultStubConf (2 * 1024 * 1024) 600 getTime
    cacheOps <- runIO $ Cache.newRRCacheOps cacheConf
    let getResolveCache n ty = do
            cxt <- newEnv putLines (\_ -> return ()) disableV6NS cacheOps tcache
            eresult <- fmap snd <$> runResolve cxt (fromString n) ty mempty
            threadDelay $ 1 * 1000 * 1000
            let convert xs =
                    [ ((dom, typ), (crs, rank))
                    | (Cache.Question dom typ _, (_, Cache.Val crs rank)) <- xs
                    ]
            (,) eresult . convert . Cache.dump <$> getCache_ cxt
        clookup cs n typ = lookup (fromString n, typ) cs
        check cs n typ = lookup (fromString n, typ) cs
        nodata = maybe False (\(crs, _rank) -> Cache.hitEither (const True) (const False) crs)

    it "answer - a" $ do
        (_, cs) <- getResolveCache "iij.ad.jp." A
        fmap snd (clookup cs "iij.ad.jp." A) `shouldSatisfy` (>= Just Cache.RankAnswer)

    it "not zone - nodata ns" $ do
        (_, cs) <- getResolveCache "iij.ad.jp." A
        check cs "ad.jp." NS `shouldSatisfy` nodata

    it "not zone - soa of nodata ns" $ do
        (_, cs) <- getResolveCache "iij.ad.jp." A
        check cs "jp." SOA `shouldSatisfy` isJust

    it "shared child zone - ns" $ do
        (_, cs) <- getResolveCache "1.1.1.1.in-addr.arpa." PTR
        check cs "arpa." NS `shouldSatisfy` isNothing

    it "shared child zone - child apex a" $ do
        (_, cs) <- getResolveCache "www.cloudflare.com." MX
        check cs "www.cloudflare.com." MX `shouldSatisfy` isJust

querySpec :: Bool -> Log.PutLines -> Spec
querySpec disableV6NS putLines = describe "query" $ do
    tcache@TimeCache{..} <- runIO newTimeCache
    let cacheConf = Cache.getDefaultStubConf (2 * 1024 * 1024) 600 getTime
    cacheOps <- runIO $ Cache.newRRCacheOps cacheConf
    let getCXT = newEnv putLines (\_ -> return ()) disableV6NS cacheOps tcache
    cxt <- runIO getCXT
    cxt4 <- runIO $ newEnv putLines (\_ -> return ()) True cacheOps tcache
    let runIterative_ ns n = runIterative cxt ns (fromString n) mempty
        runExactCXT cxt_ n ty = runResolveExact cxt_ (fromString n) ty mempty
        runJust = runExactCXT cxt
        runResolveCXT cxt_ n ty = fmap snd <$> runResolve cxt_ (fromString n) ty mempty
        runResolve_ = runResolveCXT cxt
        getReply n ty ident = do
            e <- runDNSQuery (getResultIterative (fromString n) ty) cxt mempty
            return $ replyMessage e ident [DNS.Question (fromString n) ty DNS.IN]

    let failLeft p = either (fail . ((p ++ ": ") ++) . show) pure
        printQueryError :: Show e => Either e a -> IO ()
        printQueryError = either (putStrLn . ("    QueryError: " ++) . show) (const $ pure ())
        _pprResult (msg, (ans, auth)) =
            unlines $
                ("rcode: " ++ show (DNS.rcode $ DNS.flags $ DNS.header msg))
                    : "answer:"
                    : map (("  " ++) . show) ans
                    ++ "authority:"
                    : map (("  " ++) . show) auth

        checkAnswer msg
            | null (DNS.answer msg) = Empty rcode
            | otherwise = NotEmpty rcode
          where
            rcode = DNS.rcode $ DNS.flags $ DNS.header msg
        verified rrsets
            | all rrsetValid rrsets = Verified
            | otherwise = NotVerified
        checkVAnswer (msg, (vans, _))
            | null vans = VEmpty rcode
            | otherwise = VNotEmpty rcode (verified vans)
          where
            rcode = DNS.rcode $ DNS.flags $ DNS.header msg
        checkResult = either (const Failed) (checkAnswer . fst)

    it "root-priming" $ do
        result <- runDNSQuery rootPriming cxt mempty
        printQueryError result
        either (expectationFailure . show) (`shouldSatisfy` isRight) result

    root <- runIO $ do
        icxt <- newEnv (\_ _ _ -> pure ()) (\_ -> return ()) disableV6NS cacheOps tcache
        failLeft "refresh-root error" =<< runDNSQuery refreshRoot icxt mempty

    it "iterative" $ do
        result <- runIterative_ root "iij.ad.jp."
        printQueryError result
        result `shouldSatisfy` isRight

    it "iterative - many" $ do
        result <- runIterative_ root "media-router-aol1.prod.g03.yahoodns.net."
        printQueryError result
        result `shouldSatisfy` isRight

    it "resolve-just - ns" $ do
        result <- runJust "iij.ad.jp." NS
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - a" $ do
        result <- runJust "iij.ad.jp." A
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - aaaa" $ do
        result <- runJust "iij.ad.jp." AAAA
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - mx" $ do
        result <- runJust "iij.ad.jp." MX
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - cname" $ do
        result <- runJust "porttest.dns-oarc.net." CNAME
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - ptr" $ do
        result <- runJust "1.1.1.1.in-addr.arpa." PTR
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - nx NSEC" $ do
        result <- runJust "does-not-exist.dns-oarc.net." A
        checkResult result `shouldBe` Empty DNS.NameErr

    it "resolve-just - nodata NSEC" $ do
        result <- runJust "mail.dns-oarc.net." NS
        checkResult result `shouldBe` Empty DNS.NoErr

    it "resolve-just - nx NSEC3" $ do
        result <- runJust "does-not-exist.iij.ad.jp." A
        checkResult result `shouldBe` Empty DNS.NameErr

    it "resolve-just - nodata NSEC3" $ do
        result <- runJust "www.iij.ad.jp." NS
        checkResult result `shouldBe` Empty DNS.NoErr

    it "resolve-just - nx on iterative" $ do
        result <- runJust "media-router-aol1.prod.media.yahoo.com." CNAME
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - delegation with aa" $ do
        -- `dig -4 @ns1.alibabadns.com. danuoyi.alicdn.com. A` has delegation authority section with aa flag
        result <- runExactCXT cxt4 "sc02.alicdn.com.danuoyi.alicdn.com." A
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve - cname" $ do
        result <- getCXT >>= \cxtI -> runResolveCXT cxtI "porttest.dns-oarc.net." CNAME
        printQueryError result
        let cached (rcode, rrs, _)
                | null rrs = VEmpty rcode
                | otherwise = VNotEmpty rcode NotVerified
        either (const VFailed) (either cached checkVAnswer) result
            `shouldBe` VNotEmpty DNS.NoErr Verified

    it "resolve - a via cname" $ do
        result <- runResolve_ "clients4.google.com." A
        printQueryError result
        isRight result `shouldBe` True

    it "resolve - a with DNSSEC_OK" $ do
        result <- getCXT >>= \cxtI -> runResolveCXT cxtI "iij.ad.jp." A
        printQueryError result
        isRight result `shouldBe` True
        let cached (rcode, rrs, _)
                | null rrs = VEmpty rcode
                | otherwise = VNotEmpty rcode NotVerified
        either (const VFailed) (either cached checkVAnswer) result
            `shouldBe` VNotEmpty DNS.NoErr Verified

    it "get-reply - nx via cname" $ do
        result <- getReply "media.yahoo.com." A 0
        either (const Failed) checkAnswer result `shouldBe` NotEmpty DNS.NameErr

    it "get-reply - a accumulated via cname" $ do
        result <- getReply "media-router-aol1.prod.media.yahoo.com." A 0
        either (const 0) (length . DNS.answer) result `shouldSatisfy` (> 1)
