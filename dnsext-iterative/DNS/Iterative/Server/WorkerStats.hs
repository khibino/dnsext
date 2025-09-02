{-# LANGUAGE NumericUnderscores #-}

module DNS.Iterative.Server.WorkerStats where

-- GHC packages
import Data.IORef
import Data.Maybe
import Data.List (sortBy)
import Data.Ord (comparing)

-- dnsext-* packages
import qualified DNS.Types as DNS
import DNS.Types.Time (EpochTimeUsec, diffUsec, getCurrentTimeUsec, runEpochTimeUsec)

-- this package
import DNS.Iterative.Server.Types (DoX)

{- FOURMOLU_DISABLE -}
pprWorkerStats :: Int -> [WorkerStatOP] -> IO [String]
pprWorkerStats pn ops = do
    stats <- zip [1 :: Int ..] <$> mapM getWorkerStat ops
    let isStat p = p . fst . snd
        isEnqueue (WWaitEnqueue _)  = True
        isEnqueue  _                = False
        qs = filter (isStat ((&&) <$> (/= WWaitDequeue) <*> not . isEnqueue)) stats
        {- sorted by query span -}
        sorted = sortBy (comparing $ (\(DiffT int) -> int) . snd . snd) qs
        deqs = filter (isStat (== WWaitDequeue)) stats
        getEnq (wn, (WWaitEnqueue dox, ds))  = Just (wn, dox, ds)
        getEnq  _                            = Nothing
        enqs = mapMaybe getEnq stats

        pprq (wn, st) = showDec3 wn ++ ": " ++ pprWorkerStat st
        workers []      = "no workers"
        workers triples = unwords (map (\(wn, dox, ds) -> show wn ++ ":" ++ show dox ++ ":" ++ showDiffSec1 ds) triples)
        pprdeq = " waiting dequeues: " ++ show (length deqs) ++ " workers"
        pprenq = " waiting enqueues: " ++ workers enqs

    return $ map (("  " ++ show pn ++ ":") ++) $ map pprq sorted ++ [pprdeq, pprenq]
  where
    showDec3 n
        | 100 <= n   = show n
        | 10  <= n   = ' ' : show n
        | otherwise  = "  " ++ show n
{- FOURMOLU_ENABLE -}

pprWorkerStat :: (WorkerStat, DiffTime) -> String
pprWorkerStat (stat, diff) = pad ++ diffStr ++ ": " ++ show stat
  where
    diffStr = showDiffSec1 diff
    pad = replicate (width - length diffStr) ' '
    width = 7

------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data EnqueueTarget
    = EnBegin
    | EnTap
    | EnSend
    | EnEnd
    deriving Eq

instance Show EnqueueTarget where
    show EnBegin  = "Bgn"
    show EnTap    = "Tap"
    show EnSend   = "Send"
    show EnEnd    = "End"

data WorkerStat
    = WWaitDequeue
    | WRun DNS.Question
    | WWaitEnqueue DoX
    deriving Eq

instance Show WorkerStat where
    show  WWaitDequeue                = "waiting dequeue"
    show (WRun (DNS.Question n t _))  = "quering " ++ show n ++ " " ++ show t
    show (WWaitEnqueue dox)           = "waiting enqueue " ++ show dox
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data WorkerStatOP =
    WorkerStatOP
    { setWorkerStat :: WorkerStat -> IO ()
    , getWorkerStat :: IO (WorkerStat, DiffTime)
    }
{- FOURMOLU_ENABLE -}

data WStatStore = WSStore WorkerStat TimeStamp

getWorkerStatOP :: IO WorkerStatOP
getWorkerStatOP = do
    ref <- newIORef =<< getStore WWaitDequeue
    pure $ WorkerStatOP (setStat ref) (getStat ref)
  where
    getStore stat = WSStore stat <$> getTimeStamp
    setStat ref stat = writeIORef ref =<< getStore stat
    getStat ref = do
        WSStore s ts0 <- readIORef ref
        now <- getTimeStamp
        return (s, now `diffTimeStamp` ts0)

------------------------------------------------------------

type TimeStamp = EpochTimeUsec
newtype DiffTime = DiffT Integer

getTimeStamp :: IO TimeStamp
getTimeStamp = getCurrentTimeUsec

toMicrosec :: TimeStamp -> Integer
toMicrosec eus = runEpochTimeUsec eus toMicro
  where
    toMicro sec micro = fromIntegral sec * microf + fromIntegral micro
    microf = 1_000_000

diffTimeStamp :: TimeStamp -> TimeStamp -> DiffTime
diffTimeStamp t1 t2 = DiffT (diffUsec t1 t2)

{- FOURMOLU_DISABLE -}
showDiffSec1 :: DiffTime -> String
showDiffSec1 (DiffT susec)
    | susec < 0  = '-' : str ++ "s"
    | otherwise  = str ++ "s"
  where
    usec = abs susec
    df = 100_000
    dsec = usec `quot` df
    (sec, d) = dsec `quotRem` 10
    str = show sec ++ "." ++ show d
{- FOURMOLU_ENABLE -}
