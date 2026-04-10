{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Async (concurrently_)
import Control.Monad
import Network.Run.TCP.Timeout
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import System.Environment (getArgs)
import System.Posix (Handler (Catch), installHandler, sigHUP)

import DNS.Auth.Algorithm
import DNS.Log
import DNS.Types
import Data.IORef

import qualified Auth
import qualified Axfr
import Config
import Net
import Notify
import Types
import Zone

----------------------------------------------------------------

main :: IO ()
main = do
    -- Initialization
    [conffile] <- getArgs
    (Config{..}, zonelist) <- loadConfig conffile
    withStdLogger "dug logger" Stdout INFO $ \Ops{..} -> do
        let env = Env{envPutLines = putLines}
        zones <- newZones env zonelist
        zoneAlist <- toZoneAlist zones
        -- Notify
        let (_, zonerefs) = unzip zoneAlist
        _ <- forkIO $ do
            threadDelay 1000000
            mapM_ (notifyWithZone env) zonerefs
        -- Zone updators
        let wakeupAll = sequence_ $ map zoneWakeUp zones
        void $ installHandler sigHUP (Catch wakeupAll) Nothing
        mapM_ (void . forkIO . syncZone env) zonerefs
        -- AXFR servers: TCP
        let as = map (axfrServer env zoneAlist (show cnf_tcp_port)) cnf_tcp_addrs
        -- Authoritative servers: UDP
        ss <- mapM (serverSocket cnf_udp_port) cnf_udp_addrs
        let cs = map (authServer env zoneAlist) ss
        -- Run servers
        foldr1 concurrently_ $ as ++ cs

----------------------------------------------------------------

authServer :: Env -> ZoneAlist -> Socket -> IO ()
authServer env zoneAlist s = Auth.server proto zoneAlist env
  where
    proto =
        Auth.Proto
            { recvQuery = NSB.recvFrom s 2048
            , sendReply = \sa bs -> void $ NSB.sendTo s bs sa
            }

----------------------------------------------------------------

axfrServer
    :: Env
    -> ZoneAlist
    -> ServiceName
    -> HostName
    -> IO ()
axfrServer env zoneAlist port addr =
    runTCPServer 10 (Just addr) port $
        \_ _ s -> Axfr.server env zoneAlist s

----------------------------------------------------------------

syncZone :: Env -> IORef Zone -> IO ()
syncZone env zoneref = loop
  where
    loop = do
        Zone{..} <- readIORef zoneref
        let tm
                | not zoneShouldRefresh = 0
                | not zoneReady = 10 -- retry
                | otherwise = fromIntegral $ soa_refresh $ dbSOA zoneDB
        zoneWait tm
        -- reading zone source
        updateZone env zoneref
        -- notify
        notifyWithZone env zoneref
        loop

notifyWithZone :: Env -> IORef Zone -> IO ()
notifyWithZone env zoneref = do
    Zone{..} <- readIORef zoneref
    mapM_ (notify env $ dbZone zoneDB) $ zoneNotifyAddrs
