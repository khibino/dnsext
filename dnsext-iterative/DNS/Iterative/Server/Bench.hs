{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_HADDOCK hide #-}

module DNS.Iterative.Server.Bench (
    benchServer,
    UdpServerConfig (..),
    Request,
) where

-- GHC packages
import Control.Monad (forever)

-- dnsext-* packages

-- other packages
import Network.Socket
import qualified Network.UDP as UDP

-- this package
import DNS.Iterative.Queue (
    newQueue,
    readQueue,
    writeQueue,
 )
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP

----------------------------------------------------------------
----------------------------------------------------------------
-- Benchmark

benchServer
    :: UdpServerConfig
    -> Env
    -> Bool
    -> IO ([[IO ()]], Request () -> IO (), IO (Request ()))
benchServer UdpServerConfig{..} _ True = do
    let qsize = udp_queue_size_per_pipeline * udp_pipelines_per_socket
    reqQ <- newQueue qsize
    resQ <- newQueue qsize
    let pipelines = replicate udp_pipelines_per_socket [forever $ writeQueue resQ =<< readQueue reqQ]
    return (pipelines, writeQueue reqQ, readQueue resQ)
benchServer udpconf env _ = do
    myDummy <- getSockAddr "127.1.1.1" "53"
    clntDummy <- UDP.ClientSockAddr <$> getSockAddr "127.2.1.1" "53" <*> pure []

    wstats <- getUdpWorkerStats udpconf
    (workerPipelines, enqueueReq, dequeueRes) <- getPipelines wstats udpconf env myDummy
    workers <- sequence workerPipelines

    let enqueueReq' (bs, ()) = enqueueReq (bs, clntDummy)
        dequeueRes' = (\(bs, _) -> (bs, ())) <$> dequeueRes
    return (workers, enqueueReq', dequeueRes')
  where
    getSockAddr host port = do
        as <- getAddrInfo (Just $ defaultHints{addrSocketType = Datagram}) (Just host) (Just port)
        case as of
            a : _ -> pure $ addrAddress a
            [] -> fail $ "benchServer: fail to get addr for " ++ host ++ ":" ++ port
