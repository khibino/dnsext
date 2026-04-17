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
    stats <- zip [1 :: Int ..] <$> mapM getWorkerStat ops
    let isStat p = p . fst . snd
        isEnqueue WWaitEnqueue{}  = True
        isEnqueue _               = False
        qs = filter (isStat ((&&) <$> (/= WWaitDequeue) <*> not . isEnqueue)) stats
        {- sorted by query span -}
        sorted = sortBy (comparing $ (\(DiffT int) -> int) . snd . snd) qs
        deqs = filter (isStat (== WWaitDequeue)) stats
        pprEnq  p (wn, (WWaitEnqueue _qs dox tg, ds))
            | p dox  = ((show wn ++ ":" ++ show dox ++ ":" ++ show tg ++ ":" ++ showDiffSec1 ds) :)
        pprEnq _p  _  = id
        pprEnqs
            | null pp    = "no workers"
            | otherwise  = pp
          where h2  = foldr (pprEnq (== H2))  [] stats
                dot = foldr (pprEnq (== DoT)) [] stats
                xs  = foldr (pprEnq (\x -> x /= H2 && x /= DoT)) [] stats
                pp = unwords (h2 ++ dot ++ xs)

        pprq (wn, st) = showDec3 wn ++ ": " ++ pprWorkerStat st
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
data BlockingStat
    = StatBlocking
    | StatUnblocked
    deriving Eq

instance Show BlockingStat where
    show StatBlocking   = " blocking"
    show StatUnblocked  = "unblocked"

data BlockingCause
    = CauseEnqueue
    | CauseLog
    | CauseIO
    deriving Eq

instance Show BlockingCause where
    show CauseEnqueue   = "enqueue"
    show CauseLog       = "logging"
    show CauseIO        = "I/O"

-- |
--  BlockingContext transition in worker/cacher
--
--    +---------+         +---------+         +---------+
--    |  Init   |  ---->  | Request |  ---->  |  Query  |
--    +---------+         +---------+         +----+----+
--                             ^                   |
--                             |    worker loop    |
--                             +-------------------+
--
--   --------------------------------------------------------------
--
--   e.g. internal transition under ContextRequest
--   +------------------------------------------+
--   |  Request                                 |
--   |    (ContextRequest)                      |
--   |                                          |
--   |  BlockingStat transition                 |
--   |    +-----------+       +-----------+     |
--   |    | Blocking  | ----> | Unblocked |     |
--   |    +-----------+       +-----------+     |
--   |                                          |
--   +------------------------------------------+
--
--   e.g. internal transition under ContextQuery with CauseEnqueue
--   +------------------------------------------+
--   |  Query                                   |
--   |    (ContextQuery ... CauseEnqueue ...)   |
--   |                                          |
--   |  BlockingStat transition                 |
--   |    +-----------+       +-----------+     |
--   |    | Blocking  | ----> | Unblocked |     |
--   |    +-----------+       +-----------+     |
--   |                                          |
--   +------------------------------------------+
--
data BlockingContext
    = ContextInit
    | ContextRequest
    | ContextQuery DoX Question BlockingCause String
    deriving Eq

-- |
-- >>> import Data.String
-- >>> import DNS.Types
-- >>> ContextQuery DoT (Question (fromString "example.com") A IN) CauseEnqueue "<note>"
-- enqueue: DoT: "example.com." A IN: <note>
instance Show BlockingContext where
    show  ContextInit                     = "<blocking stat unused>"
    show  ContextRequest                  = "dequeue: request"
    show (ContextQuery dox q cause note)  = show cause ++ ": " ++ show dox ++ ": " ++ showQ q ++ npp note
      where
        showQ (Question qn ty cls) = unwords [show qn, show ty, show cls]
        npp s
            | null s     = ""
            | otherwise  = ": " ++ s
{- FOURMOLU_ENABLE -}

pprBlockingStat :: (BlockingStat, BlockingContext, DiffTime) -> String
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
    , setBlocking      :: BlockingContext -> IO ()
    , setUnblocked     :: IO ()
    , getBlockingStat  :: IO (BlockingStat, BlockingContext, DiffTime)
    }
{- FOURMOLU_ENABLE -}

data WStatStore = WSStore WorkerStat TimeStamp

data WBStatStore = WBStatStore BlockingStat TimeStamp

{- FOURMOLU_DISABLE -}
data WBlockingStore =
    WBStore
    { wbkStatRef  :: IORef WBStatStore  -- consistently access, stat and timestamp pair
    , wbkContext  :: BlockingContext
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
    , getBlockingStat  = return (StatBlocking, ContextInit, DiffT (-1))
    }
{- FOURMOLU_ENABLE -}

getWorkerStatOP :: IO WorkerStatOP
getWorkerStatOP = do
    ref    <- newIORef =<< mkStore WWaitDequeue
    bkRef  <- newIORef =<< newBlocking ContextInit
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
    newBlocking context = do
        ref <- newIORef =<< mkBsStore StatBlocking
        return WBStore{wbkStatRef = ref, wbkContext = context}
    blocking bkRef context = do
        store <- newBlocking context
        writeIORef bkRef store
    unblocked bkRef = do
        WBStore{wbkStatRef = ref} <- readIORef bkRef
        writeIORef ref =<< mkBsStore StatUnblocked
    getBlocking bkRef = do
        WBStore{wbkStatRef = ref, wbkContext = context} <- readIORef bkRef
        WBStatStore bstat ts0 <- readIORef ref
        now <- getTimeStamp
        return (bstat, context, now `diffTimeStamp` ts0)

bracketBlocking :: WorkerStatOP -> BlockingContext -> IO a -> IO a
bracketBlocking wstat context = bracket_ (setBlocking wstat context) (setUnblocked wstat)

bracketDequeueReq :: WorkerStatOP -> IO a -> IO a
bracketDequeueReq wstat = bracketBlocking wstat ContextRequest

bracketEnqueue :: WorkerStatOP -> Question -> DoX -> String -> IO a -> IO a
bracketEnqueue wstat q dox note = bracketBlocking wstat (ContextQuery dox q CauseEnqueue note)

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
