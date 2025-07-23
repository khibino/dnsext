{-# LANGUAGE CPP #-}

module DNS.ThreadStats where

#if __GLASGOW_HASKELL__ >= 906

import GHC.Conc.Sync (threadStatus)
import qualified GHC.Conc.Sync as GHC
import Control.Concurrent (ThreadId, myThreadId, threadDelay)
import qualified Control.Concurrent as Concurrent
import qualified Control.Concurrent.Async as Async
import Control.Monad
import Data.List
import Data.Maybe

#else

import Control.Concurrent (ThreadId, threadDelay)
import qualified Control.Concurrent as Concurrent
import qualified Control.Concurrent.Async as Async
import Control.Monad

#endif

import Control.Concurrent.Async (Async, asyncThreadId)
import Data.List
import Data.Maybe

showTid :: ThreadId -> String
showTid tid = stripTh $ show tid
  where
    stripTh x = fromMaybe x $ stripPrefix "ThreadId " x

---

getThreadLabel :: IO String
dumpThreads :: IO [String]

#if __GLASGOW_HASKELL__ >= 906

getThreadLabel = withName (pure "<no-label>") $ \tid n -> pure $ n ++ ": " ++ showTid tid
  where
    withName nothing just = do
        tid <- myThreadId
        maybe nothing (just tid) =<< GHC.threadLabel tid

dumpThreads = do
    ts <- mapM getName =<< GHC.listThreads
    vs <- sequence [ dump tid n | (tid, Just n)  <- ts ]
    pure . map (uncurry (++)) $ sort vs
  where
    getName tid = (,) tid <$> GHC.threadLabel tid
    dump tid name = do
        st <- show <$> threadStatus tid
        let stid = showTid tid
            pad = replicate (width - length name - length stid) ' '
            val = pad ++ ": " ++ stid ++ ": " ++ st
        pure (name, val)
    width = 24

#else

getThreadLabel = pure "<thread-label not supported>"
dumpThreads = pure ["<not supported>"]

#endif

---

dumper :: ([String] -> IO ()) -> IO ()
dumper putLines = forever $ do
    putLines . (++ ["----------------------------------------"]) =<< dumpThreads
    threadDelay interval
  where
    interval = 3 * 1000 * 1000

---

listThreads :: IO [ThreadId]
threadLabel :: ThreadId -> IO (Maybe String)
labelThread :: ThreadId -> String -> IO ()

#if __GLASGOW_HASKELL__ >= 906

listThreads = GHC.listThreads
threadLabel = GHC.threadLabel
labelThread = GHC.labelThread

#else

listThreads = pure []
threadLabel _ = pure Nothing
labelThread _ _ = pure ()

#endif

---

forkIO :: String -> IO () -> IO ThreadId
forkIO name action = do
    tid <- Concurrent.forkIO action
    labelThread tid name
    pure tid

async :: String -> IO a -> IO (Async a)
async name io = do
    a <- Async.async io
    labelThread (asyncThreadId a) name
    pure a

withAsync :: String -> IO a -> (Async a -> IO b) -> IO b
withAsync name io h0 =
    Async.withAsync io h
  where
    h a = do
        labelThread (asyncThreadId a) name
        h0 a

---

withAsyncs :: [(String, IO a)] -> ([Async a] -> IO b) -> IO b
concurrently :: String -> IO a -> String -> IO b -> IO (a, b)
concurrently_ :: String -> IO a -> String -> IO b -> IO ()
race :: String -> IO a -> String -> IO b -> IO (Either a b)
race_ :: String -> IO a -> String -> IO b -> IO ()

#if __GLASGOW_HASKELL__ >= 906

withAsyncs ps h = foldr op (\f -> h (f [])) ps id
  where
    op (n, io) action = \s -> withAsync n io $ \a -> action (s . (a:))

{- FOURMOLU_DISABLE -}
concurrently nleft left nright right =
    withAsync nleft  left $ \a ->
    withAsync nright right $ \b ->
    Async.waitBoth a b
{- FOURMOLU_ENABLE -}

concurrently_ nleft left nright right = void $ concurrently nleft left nright right

{- FOURMOLU_DISABLE -}
race nleft left nright right =
    withAsync nleft  left $ \a ->
    withAsync nright right $ \b ->
    Async.waitEither a b
{- FOURMOLU_ENABLE -}

race_ nleft left nright right = void $ race nleft left nright right

#else

withAsyncs ps h = foldr op (\f -> h (f [])) ps id
  where
    op (_, io) action = \s -> Async.withAsync io $ \a -> action (s . (a:))

concurrently _ left _ right = Async.concurrently left right

concurrently_ _ left _ right = Async.concurrently_ left right

race _ left _ right = Async.race left right

race_ _ left _ right = Async.race_ left right

#endif

---

-- |
-- >>> concurrentlyList $ zip [[c] | c <- ['a'..]] [pure x | x <- [1::Int .. 5]]
-- [1,2,3,4,5]
concurrentlyList :: [(String, IO a)] -> IO [a]
concurrentlyList ps = withAsyncs ps $ mapM Async.wait

concurrentlyList_ :: [(String, IO a)] -> IO ()
concurrentlyList_ = void . concurrentlyList

raceList :: [(String, IO a)] -> IO (Async a, a)
raceList ps = withAsyncs ps Async.waitAny

raceList_ :: [(String, IO a)] -> IO ()
raceList_ = void . raceList
