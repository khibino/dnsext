{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.UDP where

-- GHC packages
import Control.Monad (forever, replicateM, when)
import Data.ByteString (ByteString)
import Control.Concurrent.STM (atomically, newTQueueIO, readTQueue, writeTQueue)

-- dnsext-* packages
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS

-- other packages
import qualified DNS.Log as Log
import Network.Socket (SockAddr)
import qualified Network.UDP as UDP
import UnliftIO (SomeException, handle)

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Queue (
    QueueSize,
    ReadQueue,
    WriteQueue,
    newQueue,
    newQueueChan,
    readQueue,
    writeQueue,
 )
import qualified DNS.Iterative.Queue as Queue
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.WorkerStats
import DNS.TAP.Schema (SocketProtocol (..))

----------------------------------------------------------------

data UdpServerConfig = UdpServerConfig
    { udp_pipelines_per_socket :: Int
    , udp_workers_per_pipeline :: Int
    , udp_queue_size_per_pipeline :: Int
    , udp_pipeline_share_queue :: Bool
    }

type Request a = (ByteString, a)
type Decoded a = (DNS.DNSMessage, a)
type Response a = (ByteString, a)

type EnqueueDec a = Decoded a -> IO ()
type EnqueueResp a = Response a -> IO ()

type UdpWorkerStats = [[WorkerStatOP]]

----------------------------------------------------------------

----------------------------------------------------------------

--                          <---------  Pipeline  -------------->
--
--                                       Iterative IO
--                                         Req Resp
--                            cache         ^   |
--                              |           |   v
--        +--------+ shared +--------+    +--------+    +--------+
-- Req -> | recver | -----> | cacher | -> | worker | -> | sender | -> Resp
--        +--------+ or any +--------|    +--------+    +--------+
--                               |                          ^
--                               +--------------------------+
--                                        Cache hit
--

----------------------------------------------------------------

udpServer :: UdpWorkerStats -> UdpServerConfig -> Server
udpServer scstats conf env port addr = do
    lsock <- UDP.serverSocket (read addr, port)
    let mysa = UDP.mySockAddr lsock
        putLn lv = logLines_ env lv Nothing . (: [])

    (mkPipelines, enqueueReq, dequeueResp) <- getPipelines scstats conf env mysa
    pipelines <- sequence mkPipelines

    let onErrorR = putLn Log.WARN . ("Server.recvRequest: error: " ++) . show
        receiver = handledLoop onErrorR (UDP.recvFrom lsock >>= enqueueReq)

    let onErrorS = putLn Log.WARN . ("Server.sendResponse: error: " ++) . show
        sender = handledLoop onErrorS (dequeueResp >>= uncurry (UDP.sendTo lsock))
    return (receiver : sender : concat pipelines)

----------------------------------------------------------------

getUdpWorkerStats :: UdpServerConfig -> IO UdpWorkerStats
getUdpWorkerStats UdpServerConfig{..} =
    replicateM udp_pipelines_per_socket $ replicateM udp_workers_per_pipeline getWorkerStatOP

----------------------------------------------------------------

getPipelines
    :: UdpWorkerStats
    -> UdpServerConfig
    -> Env
    -> SockAddr
    -> IO ([IO [IO ()]], Request UDP.ClientSockAddr -> IO (), IO (Response UDP.ClientSockAddr))
getPipelines scstats udpconf@UdpServerConfig{..} env mysa
    | length scstats /= udp_pipelines_per_socket = do
        let neq = "len:" ++ show (length scstats) ++ " =/= " ++ "conf:" ++ show udp_pipelines_per_socket
        fail $ "UDP.getPipelines: internal error, inconsistent WorkerStatOP Set: " ++ neq
    | udp_queue_size_per_pipeline <= 0 = do
        reqQ <- newQueueChan
        resQ <- newQueueChan
        {- share request queue and response queue -}
        let udpconf' = udpconf{udp_queue_size_per_pipeline = 8}
            wps = [getCacherWorkers reqQ resQ sts udpconf' env mysa | sts <- scstats]
        return (wps, writeQueue reqQ, readQueue resQ)
    | udp_pipeline_share_queue = do
        -- let qsize = udp_queue_size_per_pipeline * udp_pipelines_per_socket
        reqQ <- newTQueueIO
        resQ <- newTQueueIO
        {- share request queue and response queue -}
        let wps = [getCacherWorkers reqQ resQ sts udpconf env mysa | sts <- scstats]
        return (wps, atomically . writeTQueue reqQ, atomically $ readTQueue resQ)
    | otherwise = do
        reqQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_pipeline
        enqueueReq <- Queue.writeQueue <$> Queue.makePutAny reqQs
        resQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_pipeline
        dequeueResp <- Queue.readQueue <$> Queue.makeGetAny resQs
        let wps =
                [ getCacherWorkers reqQ resQ sts udpconf env mysa
                | reqQ <- reqQs
                | resQ <- resQs
                | sts <- scstats
                ]
        return (wps, enqueueReq, dequeueResp)

----------------------------------------------------------------

getCacherWorkers
    :: (ReadQueue rq, QueueSize rq, WriteQueue wq, QueueSize wq)
    => rq (Request UDP.ClientSockAddr)
    -> wq (Response UDP.ClientSockAddr)
    -> [WorkerStatOP]
    -> UdpServerConfig
    -> Env
    -> SockAddr
    -> IO ([IO ()])
getCacherWorkers reqQ resQ wsts UdpServerConfig{..} env mysa = do
    let logr = putLn Log.WARN . ("Server.worker: error: " ++) . show
    (resolvLoop, enqueueDec, _decQSize) <- do
        inQ <- newTQueueIO
        let loop WorkerStatOP{..} = handledLoop logr $ do
                setWorkerStat WWaitDequeue
                (reqMsg, clisa@(UDP.ClientSockAddr peersa _)) <- atomically $ readTQueue inQ
                case DNS.question reqMsg of
                    q : _ -> setWorkerStat (WRun q)
                    [] -> pure ()
                let enqueueResp' x = do
                        setWorkerStat WWaitEnqueue
                        enqueueResp (x, clisa)
                workerLogic env enqueueResp' UDP mysa peersa reqMsg
        return (loop, atomically . writeTQueue inQ, pure (-1) :: IO Int)

    let logc = putLn Log.WARN . ("Server.cacher: error: " ++) . show
        cachedLoop = handledLoop logc $ do
            (req, clisa@(UDP.ClientSockAddr peersa _)) <- readQueue reqQ
            let enqueueDec' x = enqueueDec (x, clisa)
                enqueueResp' x = enqueueResp (x, clisa)
            cacherLogic env enqueueResp' DNS.decodeAt enqueueDec' UDP mysa peersa req

    when (length wsts /= udp_workers_per_pipeline) $ do
        let neq = "len:" ++ show (length wsts) ++ " =/= " ++ "conf:" ++ show udp_workers_per_pipeline
        fail $ "UDP.getCacherWorkers: internal error, inconsistent length of WorkerStatOP list: " ++ neq

    let resolvLoops = map resolvLoop wsts
        loops = resolvLoops ++ [cachedLoop]

    return loops
  where
    putLn lv = logLines_ env lv Nothing . (: [])
    enqueueResp = writeQueue resQ

----------------------------------------------------------------

handledLoop :: (SomeException -> IO ()) -> IO () -> IO ()
handledLoop onError body = forever $ handle onError body

----------------------------------------------------------------

queueSize :: QueueSize q => q a -> IO (Int, Int)
queueSize q = do
    a <- fst <$> Queue.readSizes q
    let b = Queue.sizeMaxBound q
    return (a, b)
