{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.QUIC where

-- GHC packages
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8 ()

-- dnsext-* packages
import qualified DNS.Log as Log
import qualified DNS.Do53.Internal as DNS
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import qualified Network.QUIC as QUIC
import Network.QUIC.Server (ServerConfig (..))
import qualified Network.QUIC.Server as QUIC
import Network.TLS (Credentials (..), SessionManager)
import qualified System.TimeManager as T

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsDoQ)

----------------------------------------------------------------

quicServer :: VcServerConfig -> Server
quicServer VcServerConfig{..} env toCacher port host = do
    let quicserver = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            withLoc $ QUIC.run sconf $ go mgr
    return [quicserver]
  where
    withLoc = withLocationIOE (show host ++ ":" ++ show port ++ "/quic")
    sconf = getServerConfig vc_credentials vc_session_manager host port "doq"
    maxSize = fromIntegral vc_query_max_size
    go mgr conn = do
        info <- QUIC.getConnectionInfo conn
        let mysa = QUIC.localSockAddr info
            peersa = QUIC.remoteSockAddr info
        logLn env Log.DEBUG $ "quic-srv: accept: " ++ show peersa
        (toSender, fromX, availX) <- mkConnector
        (eof, pendings) <- mkVcState
        th <- T.registerKillThread mgr $ return ()
        let recv = do
                strm <- QUIC.acceptStream conn
                let peerInfo = PeerInfoQUIC peersa strm
                -- Without a designated thread, recvStream would block.
                (siz, bss) <- DNS.recvVC maxSize $ QUIC.recvStream strm
                if siz == 0
                    then return ("", peerInfo)
                    else do
                        when (siz > vc_slowloris_size) $ T.tickle th
                        incStatsDoQ peersa (stats_ env)
                        return (BS.concat bss, peerInfo)
            send bs peerInfo = do
                case peerInfo of
                    PeerInfoQUIC _ strm -> do
                        DNS.sendVC (QUIC.sendStreamMany strm) bs
                        QUIC.closeStream strm
                        T.tickle th
                    _ -> return ()
            receiver = receiverLoopVC env eof pendings mysa recv toCacher toSender DOQ
            sender = senderLoopVC "quic-send" env eof pendings availX send fromX
        TStat.concurrently_ "quic-send" sender "quic-recv" receiver
        logLn env Log.DEBUG $ "quic-srv: close: " ++ show peersa

getServerConfig :: Credentials -> SessionManager -> String -> PortNumber -> ByteString -> ServerConfig
getServerConfig creds sm host port alpn =
    QUIC.defaultServerConfig
        { scAddresses = [(read host, port)]
        , scALPN = Just (\_ bss -> if alpn `elem` bss then return alpn else return "")
        , scCredentials = creds
        , scUse0RTT = True
        , scSessionManager = sm
        }
