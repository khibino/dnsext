{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server (
    -- * Types
    Server,
    HostName,
    PortNumber,
    Env,
    newEnv,
    RRCacheOps (..),
    newRRCacheOps,
    TimeCache (..),
    newTimeCache,

    -- * UDP
    UdpWorkerStats,
    getUdpWorkerStats,
    UdpServerConfig (..),
    udpServer,

    -- * Virtual circuit
    VcServerConfig (..),
    tcpServer,
    http2cServer,
    http2Server,
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
) where

import DNS.Iterative.Query.Env
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.HTTP3
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.TCP
import DNS.Iterative.Server.TLS
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP
import DNS.Iterative.Server.WorkerStats
import DNS.Iterative.Stats
import DNS.RRCache (RRCacheOps (..), newRRCacheOps)
import DNS.TimeCache (TimeCache (..), newTimeCache)

import Data.ByteString.Builder

getStats :: Env -> Builder -> IO Builder
getStats Env{..} = readStats stats_
