module DNS.Log (
    new,
    Level (..),
    Output (..),
    PutLines,
) where

-- GHC packages
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Monad (when)
import System.IO (
    BufferMode (LineBuffering),
    Handle,
    hPutStr,
    hSetBuffering,
    stderr,
    stdout,
 )

-- other packages
import System.Console.ANSI (hSetSGR, hSupportsANSIColor)
import System.Console.ANSI.Types
import qualified UnliftIO.Exception as E

-- this package

data Level
    = DEBUG
    | DEMO
    | WARN
    | SYSTEM
    deriving (Eq, Ord, Show, Read)

data Output
    = Stdout
    | Stderr

instance Show Output where
    show Stdout = "Stdout"
    show Stderr = "Stderr"

type PutLines = Level -> Maybe Color -> [String] -> IO ()

new :: Output -> Level -> IO (IO (), PutLines, IO ())
new Stdout = newHandleLogger stdout
new Stderr = newHandleLogger stderr

newHandleLogger
    :: Handle -> Level -> IO (IO (), PutLines, IO ())
newHandleLogger outFh loggerLevel = do
    hSetBuffering outFh LineBuffering
    colorize <- hSupportsANSIColor outFh
    termMutex <- newEmptyMVar
    inQ <- newTQueueIO
    let logLoop = do
            let nexts x  = E.tryAny (logit x) *> logLoop
            maybe (putMVar termMutex ()) nexts =<< atomically (readTQueue inQ)
        put = logLines colorize inQ
        terminate = do
            atomically $ writeTQueue inQ Nothing
            takeMVar termMutex
    return (logLoop, put, terminate)
  where
    logLines colorize inQ lv color ~xs
        | colorize = withColor color
        | otherwise = withColor Nothing
      where
        withColor c =
            when (loggerLevel <= lv) $
                atomically $
                    writeTQueue inQ $ Just (c, xs)

    logit (Nothing, xs) = hPutStr outFh $ unlines xs
    logit (Just c, xs) = do
        hSetSGR outFh [SetColor Foreground Vivid c]
        hPutStr outFh $ unlines xs
        hSetSGR outFh [Reset]
