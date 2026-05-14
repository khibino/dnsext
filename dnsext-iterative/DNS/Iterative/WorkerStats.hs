{-# LANGUAGE NumericUnderscores #-}

module DNS.Iterative.WorkerStats where

-- GHC packages
import Control.Exception (bracket_)
import Data.IORef
import Data.List (sortBy)
import Data.Ord (comparing)

-- dnsext-* packages
import DNS.Types (Question (..))
import DNS.Types.Time (EpochTimeUsec, diffUsec, getCurrentTimeUsec, runEpochTimeUsec)

-- this package
import DNS.Iterative.Types (DoX (..))

{- FOURMOLU_DISABLE -}
pprWorkerStats :: Int -> [WorkerStatOP] -> IO [String]
pprWorkerStats _pn ops = do
    stats <- zip3 [1 :: Int ..] <$> mapM getWorkerStat ops <*> mapM getBlockingStat ops
    let getWS (_n, ws, _bks) = fst ws
        isStat p = p . getWS
        isBkStat p (_n, _ws, (bks, _bcx, _diff)) = p bks
        blockings  = filter (isBkStat (== BsBlocking))  stats
        runnings   = filter (isBkStat (== BsUnblocked)) stats
        isBkCause p (_n, _ws, (_bks, BkContext bkc _note, _diff)) = p bkc
        {- sorted by query span -}
        getDiffT (_n, _ws, (_bks, _bcx, diff)) = diff
        sorted = sortBy (comparing $ (\(DiffT int) -> int) . getDiffT) runnings
        deqs = filter (isStat (== WWaitDequeue)) stats
        pprEnq  p (wn, (WWaitEnqueue _qs dox tg, ds), _bks)
            | p dox  = ((show wn ++ ":" ++ show dox ++ ":" ++ show tg ++ ":" ++ showDiffSec1 ds) :)
        pprEnq _p  _  = id
        pprEnqs
            | null pp    = "no workers"
            | otherwise  = pp
          where h2  = foldr (pprEnq (== H2))  [] stats
                dot = foldr (pprEnq (== DoT)) [] stats
                xs  = foldr (pprEnq (\x -> x /= H2 && x /= DoT)) [] stats
                pp = unwords (h2 ++ dot ++ xs)

        pprq (wn, st, _bks) = showDec3 wn ++ ": " ++ pprWorkerStat st
        pprdeq = " waiting dequeues: " ++ show (length deqs) ++ " workers"
        pprenq = " waiting enqueues: " ++ pprEnqs

    return $ map pprq sorted ++ [pprdeq, pprenq]
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
    | EnCCase String  -- for CacheResult cases
    | EnTap
    | EnSend
    | EnEnd
    deriving Eq

instance Show EnqueueTarget where
    show  EnBegin     = "Bgn"
    show (EnCCase s)  = "CCase " ++ s
    show  EnTap       = "Tap"
    show  EnSend      = "Send"
    show  EnEnd       = "End"

data WorkerStat
    = WWaitDequeue
    | WRun Question
    | WWaitEnqueue Question DoX EnqueueTarget
    deriving Eq

instance Show WorkerStat where
    show st = case st of
        WWaitDequeue                 -> "waiting dequeue - WWaitDequeue"
        WRun q                       -> "querying" ++ pprQ q ++ " - WRun"
        WWaitEnqueue q dox tg        -> "waiting enqueue" ++ pprQ q ++ " " ++ show dox ++ " " ++ show tg ++ " - WWaitEnqueue"
      where pprQ (Question n t c) = " " ++ show n ++ " " ++  show t ++ " " ++ show c
{- FOURMOLU_ENABLE -}

------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data BkStat
    = BsBlocking
    | BsUnblocked
    deriving Eq

instance Show BkStat where
    show BsBlocking   = " blocking"
    show BsUnblocked  = "unblocked"

data BkCause
    = BcDequeueReq
    | BcEnqueueRes Question DoX
    | BcDequeue
    | BcEnqueue
    | BcIO
    deriving Eq

instance Show BkCause where
    show  BcDequeueReq         = "dequeue: request"
    show (BcEnqueueRes q dox)  = "enqueue: response: " ++ show q ++ ": " ++ show dox
    show  BcDequeue            = "dequeue"
    show  BcEnqueue            = "enqueue"
    show  BcIO                 = "I/O"

data BkContext
    = BkContext BkCause String
    deriving Eq

instance Show BkContext where
    show (BkContext cause "")    = show cause
    show (BkContext cause note)  = show cause ++ ": " ++ note
{- FOURMOLU_ENABLE -}

pprBlockingStat :: (BkStat, BkContext, DiffTime) -> String
pprBlockingStat (bstate, context, diff) = pad ++ diffStr ++ ": " ++ show bstate ++ ": " ++ show context
  where
    diffStr = showDiffSec1 diff
    pad = replicate (width - length diffStr) ' '
    width = 7

------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data WorkerStatOP =
    WorkerStatOP
    { setWorkerStat    :: WorkerStat -> IO ()
    , getWorkerStat    :: IO (WorkerStat, DiffTime)
    , setBlocking      :: BkContext -> IO ()
    , setUnblocked     :: IO ()
    , getBlockingStat  :: IO (BkStat, BkContext, DiffTime)
    }
{- FOURMOLU_ENABLE -}

data WStatStore = WSStore WorkerStat TimeStamp

data WBStatStore = WBStatStore BkStat TimeStamp

{- FOURMOLU_DISABLE -}
data WBlockingStore =
    WBStore
    { wbkStatRef  :: IORef WBStatStore  -- consistently access, stat and timestamp pair
    , wbkContext  :: BkContext
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
noopWorkerStat :: WorkerStatOP
noopWorkerStat =
    WorkerStatOP
    { setWorkerStat    = const $ return ()
    , getWorkerStat    = return (WWaitDequeue, DiffT (-1))
    , setBlocking      = const $ return()
    , setUnblocked     = return ()
    , getBlockingStat  = return (BsBlocking, BkContext BcDequeue "", DiffT (-1))
    }
{- FOURMOLU_ENABLE -}

getWorkerStatOP :: IO WorkerStatOP
getWorkerStatOP = do
    ref    <- newIORef =<< mkStore WWaitDequeue
    bkRef  <- newIORef =<< mkBkStore :: IO (IORef WBlockingStore)
    return
        WorkerStatOP
        { setWorkerStat = setStat ref
        , getWorkerStat = getStat ref
        , setBlocking = blocking bkRef
        , setUnblocked = unblocked bkRef
        , getBlockingStat = getBlocking bkRef
        }
  where
    mkStore stat = WSStore stat <$> getTimeStamp
    setStat ref stat = writeIORef ref =<< mkStore stat
    getStat ref = do
        WSStore stat ts0 <- readIORef ref
        now <- getTimeStamp
        return (stat, now `diffTimeStamp` ts0)
    --
    mkBsStore bstat = WBStatStore bstat <$> getTimeStamp
    mkBkStore = do
        ref <- newIORef =<< mkBsStore BsUnblocked
        return WBStore{wbkStatRef = ref, wbkContext = BkContext BcDequeue "req"}
    blocking bkRef context = do
        ref <- newIORef =<< mkBsStore BsBlocking
        writeIORef bkRef WBStore{wbkStatRef = ref, wbkContext = context}
    unblocked bkRef = do
        WBStore{wbkStatRef = ref} <- readIORef bkRef
        writeIORef ref =<< mkBsStore BsUnblocked
    getBlocking bkRef = do
        WBStore{wbkStatRef = ref, wbkContext = context} <- readIORef bkRef
        WBStatStore bstat ts0 <- readIORef ref
        now <- getTimeStamp
        return (bstat, context, now `diffTimeStamp` ts0)

bracketBlocking :: WorkerStatOP -> BkContext -> IO a -> IO a
bracketBlocking wstat context = bracket_ (setBlocking wstat context) (setUnblocked wstat)

bracketDequeueReq :: WorkerStatOP -> IO a -> IO a
bracketDequeueReq wstat = bracketBlocking wstat (BkContext BcDequeueReq "")

bracketEnqueueRes :: WorkerStatOP -> Question -> DoX -> IO a -> IO a
bracketEnqueueRes wstat q dox = bracketBlocking wstat (BkContext (BcEnqueueRes q dox) "")

bracketEnqueue :: WorkerStatOP -> String -> IO a -> IO a
bracketEnqueue wstat tag = bracketBlocking wstat (BkContext BcEnqueue tag)

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
