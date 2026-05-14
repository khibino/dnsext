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
        isBkStat p (_n, _ws, (bks, _ctx, _cause, _diff)) = p bks
        ablockings  = filter (isBkStat (== StatBlocking))  stats
        runnings    = filter (isBkStat (== StatUnblocked)) stats
        isBkCause p (_n, _ws, (_bks, _ctx, cause, _diff)) = p cause
        requests    = filter (isBkCause (== CauseRequest))  ablockings
        responses   = filter (isBkCause (== CauseResponse)) ablockings
        blockings   = filter (isBkCause (`notElem` [CauseRequest, CauseResponse])) ablockings
        {- sorted by query span -}
        getDiffT (_n, _ws, (_bks, _ctx, _cause, diff)) = diff
        sorted = sortBy (comparing $ (\(DiffT int) -> int) . getDiffT) $ runnings ++ blockings
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

        pprq (wn, _st, bks) = showDec3 wn ++ ": " ++ pprBlockingStat bks
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
    = CauseUndef
    | CauseRequest
    | CauseResponse
    | CauseEnqueue  String
    | CauseLog      String
    | CauseIO       String
    deriving Eq

instance Show BlockingCause where
    show  CauseUndef           = "<blocking cause unused>"
    show  CauseRequest         = "dequeue: request"
    show  CauseResponse        = "enqueue: response"
    show (CauseEnqueue  note)  = "enqueue: " ++ note
    show (CauseLog      note)  = "logging: " ++ note
    show (CauseIO       note)  = "I/O: " ++ note

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
--   e.g. internal transition under CauseRequest
--   +------------------------------------------+
--   |  CauseRequest                            |
--   |                                          |
--   |  BlockingStat transition                 |
--   |    +-----------+       +-----------+     |
--   |    | Blocking  | ----> | Unblocked |     |
--   |    +-----------+       +-----------+     |
--   |                                          |
--   +------------------------------------------+
--
--   e.g. internal transition under (CauseEnqueue "dnstap")
--   +------------------------------------------+
--   |  CauseEnqueue "dnstap"                   |
--   |                                          |
--   |  BlockingStat transition                 |
--   |    +-----------+       +-----------+     |
--   |    | Blocking  | ----> | Unblocked |     |
--   |    +-----------+       +-----------+     |
--   |                                          |
--   +------------------------------------------+
--
data BlockingContext
    = ContextRequest
    | ContextQuery DoX Question
    deriving Eq

-- |
-- >>> import Data.String
-- >>> import DNS.Types
-- >>> ContextQuery DoT (Question (fromString "example.com") A IN)
-- DoT: "example.com." A IN
instance Show BlockingContext where
    show  ContextRequest       = ""
    show (ContextQuery dox q)  = show dox ++ ": " ++ showQ q
      where
        showQ (Question qn ty cls) = unwords [show qn, show ty, show cls]
{- FOURMOLU_ENABLE -}

pprBlockingStat :: (BlockingStat, BlockingContext, BlockingCause, DiffTime) -> String
pprBlockingStat (bstate, context, cause, diff) =
    pad ++ diffStr ++ ": " ++ show bstate ++ npp (show context) ++ ": " ++ show cause
  where
    diffStr = showDiffSec1 diff
    pad = replicate (width - length diffStr) ' '
    width = 7
    npp s
        | null s     = ""
        | otherwise  = ": " ++ s

------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data WorkerStatOP =
    WorkerStatOP
    { setWorkerStat    :: WorkerStat -> IO ()
    , getWorkerStat    :: IO (WorkerStat, DiffTime)
    , setQuery         :: DoX -> Question -> IO ()
    , setRequest       :: IO ()
    , setBlocking      :: BlockingCause -> IO ()
    , setUnblocked     :: IO ()
    , getBlockingStat  :: IO (BlockingStat, BlockingContext, BlockingCause, DiffTime)
    }
{- FOURMOLU_ENABLE -}

data WStatStore = WSStore WorkerStat TimeStamp

data WBStatStore = WBStatStore BlockingStat TimeStamp

{- FOURMOLU_DISABLE -}
data WBlockingStore =
    WBStore
    { wbkStatRef  :: IORef WBStatStore  -- consistently access, stat and timestamp pair
    , wbkCause    :: BlockingCause
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
noopWorkerStat :: WorkerStatOP
noopWorkerStat =
    WorkerStatOP
    { setWorkerStat    = const $ return ()
    , getWorkerStat    = return (WWaitDequeue, DiffT (-1))
    , setQuery         = \_ _ -> return ()
    , setRequest       = return ()
    , setBlocking      = \_ -> return ()
    , setUnblocked     = return ()
    , getBlockingStat  = return (StatBlocking, ContextRequest, CauseUndef, DiffT (-1))
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
getWorkerStatOP :: IO WorkerStatOP
getWorkerStatOP = do
    ref     <- newIORef =<< mkStore WWaitDequeue
    ctxRef  <- newIORef     ContextRequest
    blkRef  <- newIORef =<< newBlkStore CauseUndef
    return
        WorkerStatOP
        { setWorkerStat    = setStat ref
        , getWorkerStat    = getStat ref
        , setQuery         = \dox q -> writeIORef ctxRef $ ContextQuery dox q
        , setRequest       = writeIORef ctxRef ContextRequest
        , setBlocking      = blocking  blkRef
        , setUnblocked     = unblocked blkRef
        , getBlockingStat  = getBlkStat ctxRef blkRef
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
    newBlkStore cause = do
        ref <- newIORef =<< mkBsStore StatBlocking
        return WBStore{wbkStatRef = ref, wbkCause = cause}
    blocking blkRef cause = do
        store <- newBlkStore cause
        writeIORef blkRef store
    unblocked bkRef = do
        WBStore{wbkStatRef = ref} <- readIORef bkRef
        writeIORef ref =<< mkBsStore StatUnblocked
    getBlkStat ctxRef blkRef = do
        context <- readIORef ctxRef
        WBStore{wbkStatRef = ref, wbkCause = cause} <- readIORef blkRef
        WBStatStore bstat ts0 <- readIORef ref
        now <- getTimeStamp
        return (bstat, context, cause, now `diffTimeStamp` ts0)
{- FOURMOLU_ENABLE -}

contextSetQuery :: WorkerStatOP -> DoX -> Question -> IO ()
contextSetQuery = setQuery

contextClear :: WorkerStatOP -> IO ()
contextClear = setRequest

bracketBlocking :: WorkerStatOP -> BlockingCause -> IO a -> IO a
bracketBlocking wstat cause = bracket_ (setBlocking wstat cause) (setUnblocked wstat)

blockingRequest :: WorkerStatOP -> IO a -> IO a
blockingRequest wstat = bracketBlocking wstat CauseRequest

blockingResponse :: WorkerStatOP -> IO a -> IO a
blockingResponse wstat = bracketBlocking wstat CauseResponse

blockingEnqueue :: WorkerStatOP -> String -> IO a -> IO a
blockingEnqueue wstat note = bracketBlocking wstat (CauseEnqueue note)

blockingLog :: WorkerStatOP -> String -> IO a -> IO a
blockingLog wstat note = bracketBlocking wstat (CauseLog note)

blockingIO :: WorkerStatOP -> String -> IO a -> IO a
blockingIO wstat note = bracketBlocking wstat (CauseIO note)

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
