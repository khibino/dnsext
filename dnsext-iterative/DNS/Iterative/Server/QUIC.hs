{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.QUIC where

-- GHC packages
import Control.Concurrent (forkIO)
import Control.Concurrent.STM (isEmptyTQueue)
import qualified Data.ByteString as BS

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import qualified Network.QUIC as QUIC
import qualified Network.QUIC.Internal as QUIC
import Network.QUIC.Server (ServerConfig (..))
import qualified Network.QUIC.Server as QUIC
import Network.TLS (Credentials (..), SessionManager)

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsDoQ, sessionStatsDoQ)

----------------------------------------------------------------

quicServers :: VcServerConfig -> ServerActions
quicServers VcServerConfig{..} env toCacher ss = do
    -- fixme: withLocationIOE naming
    let quicserver = withLocationIOE "QUIC" $ QUIC.runWithSockets ss sconf go
    return [quicserver]
  where
    tmicro = vc_idle_timeout * 1_000_000
    sconf = getServerConfig vc_credentials vc_session_manager "doq"
    maxSize = fromIntegral vc_query_max_size
    go conn = sessionStatsDoQ (stats_ env) $ do
        info <- QUIC.getConnectionInfo conn
        putStr $ unlines $ "" : "quic: sess:" : map ("  " ++) (lines $ show info)
        let mysa = QUIC.localSockAddr info
            peersa = QUIC.remoteSockAddr info
            waitInput = pure $ (guard . not =<<) . isEmptyTQueue $ QUIC.inputQ conn
        (vcSess@VcSession{..}, toSender, fromX) <- initVcSession waitInput tmicro
        _ <- forkIO $ dumperVcSession vcSess
        let recv = do
                strm <- QUIC.acceptStream conn
                let peerInfo = PeerInfoQUIC peersa strm
                putStrLn $ "quic: recv: " ++ show peerInfo
                -- Without a designated thread, recvStream would block.
                (siz, bss) <- DNS.recvVC maxSize $ QUIC.recvStream strm
                if siz == 0
                    then updateVcTimeout tmicro vcTimeout_ $> ("", peerInfo)
                    else do
                        when (siz > vc_slowloris_size) $ updateVcTimeout tmicro vcTimeout_
                        incStatsDoQ peersa (stats_ env)
                        return (BS.concat bss, peerInfo)
            send bs peerInfo = do
                case peerInfo of
                    PeerInfoQUIC _ strm -> do
                        DNS.sendVC (QUIC.sendStreamMany strm) bs
                        QUIC.closeStream strm
                        updateVcTimeout tmicro vcTimeout_
                    _ -> return ()
            receiver = receiverVC "quic-recv" env vcSess recv toCacher (mkInput mysa toSender DOQ)
            sender = senderVC "quic-send" env vcSess send fromX
        TStat.concurrently_ "quic-send" sender "quic-recv" receiver
        putStrLn $
          unlines
          [ "************************************"
          , "*  quic-send, quic-recv, finished  *"
          , "************************************"
          ]

getServerConfig :: Credentials -> SessionManager -> ByteString -> ServerConfig
getServerConfig creds sm alpn =
    QUIC.defaultServerConfig
        { scALPN = Just (\_ bss -> if alpn `elem` bss then return alpn else return "")
        , scCredentials = creds
        , scUse0RTT = True
        , scSessionManager = sm
        }
