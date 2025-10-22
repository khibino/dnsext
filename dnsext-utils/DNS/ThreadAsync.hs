
module DNS.ThreadAsync where

-- GHC internal
import GHC.Conc.Sync (labelThread)

-- base
import Control.Monad

-- async
import Control.Concurrent.Async (Async, asyncThreadId)
import qualified Control.Concurrent.Async as Async

{- FOURMOLU_DISABLE -}
async :: String -> IO a -> IO (Async a)
withAsync :: String -> IO a -> (Async a -> IO b) -> IO b
withAsyncs :: [(String, IO a)] -> ([Async a] -> IO b) -> IO b
concurrently :: String -> IO a -> String -> IO b -> IO (a, b)
concurrently_ :: String -> IO a -> String -> IO b -> IO ()
race :: String -> IO a -> String -> IO b -> IO (Either a b)
race_ :: String -> IO a -> String -> IO b -> IO ()
concurrentlyList :: [(String, IO a)] -> IO [a]
concurrentlyList_ :: [(String, IO a)] -> IO ()
raceList :: [(String, IO a)] -> IO (Async a, a)
raceList_ :: [(String, IO a)] -> IO ()
{- FOURMOLU_ENABLE -}

async name io = do
    a <- Async.async io
    labelThread (asyncThreadId a) name
    pure a

withAsync name io h0 =
    Async.withAsync io h
  where
    h a = do
        labelThread (asyncThreadId a) name
        h0 a

withAsyncs ps h = foldr op (\f -> h (f [])) ps id
  where
    op (n, io) action = \s -> withAsync n io $ \a -> action (s . (a :))

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

-- |
-- >>> concurrentlyList $ zip [[c] | c <- ['a'..]] [pure x | x <- [1::Int .. 5]]
-- [1,2,3,4,5]
concurrentlyList ps = withAsyncs ps $ mapM Async.wait

concurrentlyList_ = void . concurrentlyList

raceList ps = withAsyncs ps Async.waitAny

raceList_ = void . raceList
