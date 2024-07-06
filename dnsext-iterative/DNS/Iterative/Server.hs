{-# LANGUAGE RecordWildCards #-}

-- | The server side of full resolver.
module DNS.Iterative.Server (
    -- * Types
    module DNS.Iterative.Query.Env,
    module DNS.Iterative.Server.Types,
    RRCacheOps (..),
    newRRCacheOps,
    TimeCache (..),
    newTimeCache,
    module Network.Socket,

    -- * Pipeline
    mkPipeline,
    getWorkerStats,

    -- * UDP
    UdpServerConfig (..),
    udpServer,

    -- * Virtual circuit
    VcServerConfig (..),
    tcpServer,
    http2Server,
    http2cServer,
    http3Server,
    tlsServer,
    quicServer,

    -- * WorkerStat
    WorkerStat (..),
    WorkerStatOP (..),
    pprWorkerStats,
    pprWorkerStat,

    -- * Stats
    getStats,

    -- * Tests
    Recv,
    Send,
    VcEof,
    VcPendings,
    VcRespAvail,
    mkVcState,
    mkConnector,
    mkInput,
    receiverLoopVC,
    senderLoopVC,
) where

import DNS.Iterative.Query.Env
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.HTTP3
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.TCP
import DNS.Iterative.Server.TLS
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP
import DNS.Iterative.Server.WorkerStats
import DNS.Iterative.Stats
import DNS.RRCache (RRCacheOps (..), newRRCacheOps)
import qualified DNS.RRCache as RRCache
import DNS.TimeCache (TimeCache (..), newTimeCache)

import Control.Concurrent (getNumCapabilities)
import Data.ByteString.Builder
import Data.String (fromString)
import Network.Socket

getStats :: Env -> Builder -> IO Builder
getStats Env{..} prefix =
    (<>) <$> readStats stats_ prefix <*> getGlobalStats
  where
    getGlobalStats = (<>) <$> (cacheCount <$> getCache_) <*> (info <$> getNumCapabilities)
    cacheCount c = prefix <> fromString ("rrset_cache_count " <> show (RRCache.size c) <> "\n")
    info cap = prefix <> fromString ("info{threads=\"" ++ show cap ++ "\", version=\"0.0.0.20240628\"} 1\n")
