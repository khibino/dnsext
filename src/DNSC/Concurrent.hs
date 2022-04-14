module DNSC.Concurrent (
  forkProcessQ,
  forkLoop,
  forksProcessQ,
  forksLoop,
  ) where

import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Monad (unless, replicateM_)
import Data.IORef (newIORef, readIORef, writeIORef)

import Control.Concurrent.Async (async, wait)


forkProcessQ :: (a -> IO ())
           -> IO (a -> IO (), IO ())
forkProcessQ = forksProcessQ 1

forkLoop :: IO () -> IO (IO ())
forkLoop = forksLoop 1

forksProcessQ :: Int -> (a -> IO ())
              -> IO (a -> IO (), IO ())
forksProcessQ n body = do
  inQ <- newChan
  let enqueue = writeChan inQ . Just
      issueQuit = replicateM_ n $ writeChan inQ Nothing
      loop = maybe (return ()) ((*> loop) . body) =<< readChan inQ

  waitQuit <- forksWithWait $ replicate n loop
  return (enqueue, issueQuit *> waitQuit)

forksLoop :: Int -> IO () -> IO (IO ())
forksLoop n body = do
  qref <- newIORef False
  let loop = do
        isQuit <- readIORef qref
        unless isQuit $ body *> loop
  waitQuit <- forksWithWait $ replicate n loop
  return $ writeIORef qref True *> waitQuit

forksWithWait :: [IO ()] -> IO (IO ())
forksWithWait bodies = do
  ts <- mapM async bodies
  let waitQuit = mapM_ wait ts
  return waitQuit
