{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Log (
    newStdLogger,
    newHandleLogger,
    LogUtils (..),
    --
    Level (..),
    pattern DEMO,
    pattern WARN,
    pattern SYSTEM,
    --
    StdHandle (..),
    stdHandle,
    Logger,
    PutLines,
    KillLogger,
    ReopenLogger,
) where

-- GHC packages
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad (when)
import Data.Functor
import Numeric.Natural
import System.IO (
    BufferMode (LineBuffering),
    Handle,
    hPutStrLn,
    hSetBuffering,
    stderr,
    stdout,
 )

-- other packages
import System.Console.ANSI (hSetSGR, hSupportsANSIColor)
import System.Console.ANSI.Types

-- this package

{- FOURMOLU_DISABLE -}
data Level
    = DEBUG   -- ^ Most detailed.
    | INFO    -- ^ For demonstration
    | NOTICE  -- ^ (reserved for demo)
    | WARNING -- ^ Not error but caution is necessary (default)
    | ERR     -- ^ Fatal
    | CRIT    -- ^ (reserved)
    | ALERT   -- ^ (reserved)
    | EMERG   -- ^ (reserved)
    deriving (Eq, Ord, Show, Read)
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
{- levels for backword compat  -}
-- | Alias for 'INFO'
pattern DEMO     :: Level
pattern DEMO     = INFO
-- | Alias for 'WARNING'
pattern WARN     :: Level
pattern WARN     = WARNING
-- | Alias for 'ERR'
pattern SYSTEM   :: Level
pattern SYSTEM   = ERR
{- FOURMOLU_ENABLE -}

data StdHandle
    = Stdout
    | Stderr

instance Show StdHandle where
    show Stdout = "<stdout>"
    show Stderr = "<stderr>"

data LogUtils = LogUtils
    { runLogger :: IO Logger
    , putLinesSTM :: PutLines STM
    , putLines :: PutLines IO
    , killLogger :: IO KillLogger
    }

type Logger = ()
type PutLines m = Level -> Maybe Color -> [String] -> m ()
type KillLogger = ()
type ReopenLogger = ()

-- | Creating 'LogUtils' for stdout or stderr.
newStdLogger :: StdHandle -> Level -> IO LogUtils
newStdLogger oh lv = newHandleLogger (pure id) (pure $ stdHandle oh) (\_ -> pure ()) lv (\lu _ -> pure lu)

{- FOURMOLU_DISABLE -}
-- | Creating logger based on 'Handle'.
newHandleLogger
    :: IO ShowS           -- ^ Getting log source
    -> IO Handle          -- ^ Open
    -> (Handle -> IO ())  -- ^ Close
    -> Level              -- ^ Log level
    -> (LogUtils -> IO ReopenLogger -> IO a) -- ^ Function which typically return 'LogUtils'
    -> IO a
newHandleLogger = withHandleLogger queueBound
{- FOURMOLU_ENABLE -}

stdHandle :: StdHandle -> Handle
stdHandle Stdout = stdout
stdHandle Stderr = stderr

{- limit waiting area on server to constant size -}
queueBound :: Natural
queueBound = 8

{- FOURMOLU_DISABLE -}
withHandleLogger
    :: Natural -> IO ShowS -> IO Handle -> (Handle -> IO ()) -> Level
    -> (LogUtils -> IO ReopenLogger -> IO a) -> IO a
withHandleLogger qsize getM open close loggerLevel k = do
    outFh <- open'
    colorize  <- hSupportsANSIColor outFh
    inQ       <- newTBQueueIO qsize
    mvar      <- newEmptyMVar
    let lu = LogUtils
                { runLogger = loggerLoop inQ mvar outFh
                , putLinesSTM = putLinesSTM_ colorize inQ
                , putLines = putLinesIO_  colorize inQ
                , killLogger = killLogger inQ mvar
                }
        reopen  = reopenLogger colorize inQ
    k lu reopen
  where
    killLogger inQ mvar = do
        atomically $ writeTBQueue inQ $ \bk _  _  -> bk
        takeMVar mvar

    reopenLogger colorize inQ = do
        putLinesIO_ colorize inQ INFO Nothing ["re-opening log."]
        atomically $ writeTBQueue inQ $ \_  rk _  -> rk

    putLinesSTM_  = putLines_ (pure id) id
    putLinesIO_   = putLines_  getM     atomically

    putLines_ getM' toM colorize inQ lv ~color ~xs
        | colorize   = withColor color
        | otherwise  = withColor Nothing
      where
        withColor ~c = when (loggerLevel <= lv) $ do
            mdfy <- getM'
            toM    $ writeTBQueue inQ $ \_  _  ck -> ck c (map mdfy xs)

    loggerLoop inQ mvar = loop
      where
        loop outFh = do
            me <- atomically (readTBQueue inQ)
            let close'   = close outFh >> putMVar mvar ()
                reopen'  = close outFh >> open' >>= loop
            me close' reopen' $ \c xs -> logit outFh c xs >> loop outFh

    open' = open >>= \outFh -> hSetBuffering outFh LineBuffering $> outFh

    logit outFh Nothing  xs = mapM_ (hPutStrLn outFh) xs
    logit outFh (Just c) xs = do
        hSetSGR outFh [SetColor Foreground Vivid c]
        mapM_ (hPutStrLn outFh) xs
        hSetSGR outFh [Reset]
{- FOURMOLU_ENABLE -}
