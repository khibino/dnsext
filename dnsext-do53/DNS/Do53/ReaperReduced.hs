{-# LANGUAGE RecordWildCards    #-}

module DNS.Do53.ReaperReduced (
      -- * Example: Regularly cleaning a cache
      -- $example1

      -- * Settings
      ReaperSettings
    , defaultReaperSettings
      -- * Accessors
    , reaperAction
    , reaperCallback
    , reaperDelay
    , reaperCons
    , reaperNull
    , reaperEmpty
      -- * Type
    , Reaper(..)
      -- * Creation
    , mkReaper
      -- * Helper
    , mkListAction
    ) where

import Control.Concurrent (forkIO, threadDelay, killThread, ThreadId)
import Control.Exception (mask_)
import Data.IORef (IORef, newIORef, readIORef, writeIORef, atomicModifyIORef)

-- traditional semantics about thunk of a',
-- update pointer to thunk with unlock, then reduce thunk
atomicModifyIORef'' :: IORef a -> (a -> (a, b)) -> IO b
atomicModifyIORef'' ref f = do
    b <- atomicModifyIORef ref $ \a ->
      case f a of
        (a',b) -> (a', a' `seq` b)
    b `seq` return b

data ReaperSettings workload item = ReaperSettings
    { reaperAction :: IO (workload -> Maybe workload)
    , reaperCallback :: Maybe workload -> IO ()
    , reaperDelay :: Int
    , reaperCons :: item -> workload -> workload
    , reaperNull :: workload -> Bool
    , reaperEmpty :: workload
    }

-- | Default @ReaperSettings@ value, biased towards having a list of work
-- items.
defaultReaperSettings :: ReaperSettings [item] item
defaultReaperSettings = ReaperSettings
    { reaperAction   = return Just
    , reaperCallback = const $ return ()
    , reaperDelay    = 30000000
    , reaperCons     = (:)
    , reaperNull     = null
    , reaperEmpty    = []
    }

-- | A data structure to hold reaper APIs.
data Reaper workload item = Reaper {
    -- | Adding an item to the workload
    reaperAdd  :: item -> IO ()
    -- | Reading workload.
  , reaperRead :: IO workload
    -- | Pruning independently of the Reaper thread
  , reaperPrune :: IO ()
    -- | Stopping the reaper thread if exists.
    --   The current workload is returned.
  , reaperStop :: IO workload
    -- | Killing the reaper thread immediately if exists.
  , reaperKill :: IO ()
  }

-- | State of reaper.
data State workload = NoReaper           -- ^ No reaper thread
                    | Workload workload  -- ^ The current jobs

-- | Create a reaper addition function. This function can be used to add
-- new items to the workload. Spawning of reaper threads will be handled
-- for you automatically.
mkReaper :: ReaperSettings workload item -> IO (Reaper workload item)
mkReaper settings@ReaperSettings{..} = do
    stateRef  <- newIORef NoReaper
    lookupRef <- newIORef NoReaper  {- only allowed after reduced thunk pointer -}
    tidRef    <- newIORef Nothing
    return Reaper {
        reaperAdd   = add settings stateRef lookupRef tidRef
      , reaperRead  = readRef lookupRef
      , reaperPrune = do (postPrune, _next) <- pruneActions settings stateRef lookupRef tidRef
                         postPrune
      , reaperStop  = stop stateRef
      , reaperKill  = kill tidRef
      }
  where
    readRef lookupRef = do
        mx <- readIORef lookupRef
        case mx of
            NoReaper    -> return reaperEmpty
            Workload wl -> return wl
    stop stateRef = atomicModifyIORef'' stateRef $ \mx ->
        case mx of
            NoReaper   -> (NoReaper, reaperEmpty)
            Workload x -> (Workload reaperEmpty, x)
    kill tidRef = do
        mtid <- readIORef tidRef
        case mtid of
            Nothing  -> return ()
            Just tid -> killThread tid

add :: ReaperSettings workload item
    -> IORef (State workload) -> IORef (State workload) -> IORef (Maybe ThreadId)
    -> item -> IO ()
add settings@ReaperSettings{..} stateRef lookupRef tidRef item =
    mask_ $ do
      next <- atomicModifyIORef'' stateRef cons
      next
  where
    cons NoReaper      = let thunk = Workload (reaperCons item reaperEmpty)
                         in (thunk, writeIORef lookupRef thunk *> spawn settings stateRef lookupRef tidRef )
    cons (Workload wl) = let thunk = Workload (reaperCons item wl)
                         in (thunk, writeIORef lookupRef thunk)

spawn :: ReaperSettings workload item
      -> IORef (State workload) -> IORef (State workload) -> IORef (Maybe ThreadId)
      -> IO ()
spawn settings stateRef lookupRef tidRef = do
    tid <- forkIO $ reaper settings stateRef lookupRef tidRef
    writeIORef tidRef $ Just tid

reaper :: ReaperSettings workload item
       -> IORef (State workload) -> IORef (State workload) -> IORef (Maybe ThreadId)
       -> IO ()
reaper settings@ReaperSettings{..} stateRef lookupRef tidRef = do
    threadDelay reaperDelay
    (postPrune, next) <- pruneActions settings stateRef lookupRef tidRef
    postPrune
    next

pruneActions :: ReaperSettings workload item
             -> IORef (State workload) -> IORef (State workload) -> IORef (Maybe ThreadId)
             -> IO (IO (), IO ())
pruneActions settings@ReaperSettings{..} stateRef lookupRef tidRef = do
    prune <- reaperAction
    atomicModifyIORef'' stateRef (checkPrune prune)
  where
    checkPrune _ NoReaper   = error "Control.Reaper.reaper: unexpected NoReaper (1)"
    checkPrune prune current@(Workload wl) = case mayWl' of
      Nothing            ->      (current,  (callback,
                                             reaper settings stateRef lookupRef tidRef) )
      Just wl'
        -- If there is no job, reaper is terminated.
        | reaperNull wl' ->      (NoReaper, (callback *> writeIORef lookupRef NoReaper,
                                             writeIORef tidRef Nothing)       )
        -- If there are jobs, carry them out.
        | otherwise      ->  let thunk = Workload wl'
                             in  (thunk,    (callback *> writeIORef lookupRef thunk,
                                             reaper settings stateRef lookupRef tidRef) )
      where
        mayWl' = prune wl
        callback = reaperCallback mayWl'

-- | A helper function for creating 'reaperAction' functions. You would
-- provide this function with a function to process a single work item and
-- return either a new work item, or @Nothing@ if the work item is
-- expired.
mkListAction :: (item -> IO (Maybe item'))
             -> [item]
             -> IO ([item'] -> [item'])
mkListAction f =
    go id
  where
    go front [] = return front
    go front (x:xs) = do
        my <- f x
        let front' =
                case my of
                    Nothing -> front
                    Just y  -> front . (y:)
        go front' xs

{- $example1
Example of caching fibonacci numbers like Reaper

-- @

import Data.Time (UTCTime, getCurrentTime, diffUTCTime)
import DNS.Do53.ReaperReduced
import Control.Concurrent (threadDelay)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Control.Monad (forever)
import System.IO (BufferMode (..), hSetBuffering, stdout)
import System.Random (getStdRandom, randomR)

fib :: Int -> Int
fib 0 = 0
fib 1 = 1
fib n = fib (n-1) + fib (n-2)

type Cache = Map Int (Int, UTCTime)

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  reaper <- mkReaper defaultReaperSettings
    { reaperAction = clean
    , reaperCallback =
        \x -> case x of
                Just m | Map.null m ->  putStrLn "clean: empty"
                _                   ->  putStrLn "clean: not empty"
    , reaperDelay = 1000000 * 2 -- Clean 2 seconds after
    , reaperCons = \(k, v) -> Map.insert k v
    , reaperNull = Map.null
    , reaperEmpty = Map.empty
    }
  forever $ do
    fibArg <- System.Random.getStdRandom (System.Random.randomR (30,34))
    cache <- reaperRead reaper
    let cachedResult = Map.lookup fibArg cache
    case cachedResult of
      Just (fibResult, _createdAt) -> putStrLn $ "Found in cache: `fib " ++ show fibArg ++ "` " ++ show fibResult
      Nothing -> do
        let fibResult = fib fibArg
        putStrLn $ "Calculating `fib " ++ show fibArg ++ "` " ++ show fibResult
        time <- getCurrentTime
        reaperAdd reaper (fibArg, (fibResult, time))
    threadDelay 1000000 -- 1 second

-- Remove items > 10 seconds old
clean :: IO (Cache -> Maybe Cache)
clean = do
  currentTime <- getCurrentTime
  let prune oldMap = Just (Map.filter (\ (_, createdAt) -> currentTime `diffUTCTime` createdAt < 10.0) oldMap)
  return prune

-- @

 -}
