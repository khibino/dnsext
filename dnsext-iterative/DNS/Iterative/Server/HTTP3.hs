{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP3 (
    http3Server,
) where

-- GHC packages
import Control.Concurrent.STM (atomically)
import qualified Control.Exception as E
import Control.Monad (when)
import Data.ByteString.Builder (byteString)
import qualified Data.ByteString.Char8 as C8

-- dnsext-* packages
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages

import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import qualified Network.HTTP3.Server as H3
import qualified Network.QUIC.Server as QUIC
import qualified System.TimeManager as T

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsDoH3)

----------------------------------------------------------------
http3Server :: VcServerConfig -> Server
http3Server VcServerConfig{..} env toCacher port host = do
    let http3server = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            withLoc $ QUIC.run sconf $ \conn ->
                withLoc $ H3.run conn (conf mgr) $ doHTTP env toCacher
    return [http3server]
  where
    withLoc = withLocationIOE (show host ++ ":" ++ show port ++ "/h3")
    sconf = getServerConfig vc_credentials vc_session_manager host port "h3"
    conf mgr =
        H3.Config
            { confHooks = H3.defaultHooks
            , confTimeoutManager = mgr
            , confPositionReadMaker = H3.defaultPositionReadMaker
            }

doHTTP
    :: Env
    -> ToCacher
    -> H2.Server
doHTTP env toCacher req aux sendResponse = do
    let mysa = H2.auxMySockAddr aux
        peersa = H2.auxPeerSockAddr aux
        peerInfo = PeerInfoVC peersa
    logLn env Log.DEBUG $ "h3-srv: accept: " ++ show peersa
    (toSender, fromX, availX) <- mkConnector
    (eof, pendings) <- mkVcState
    let receiver = loop 1 *> atomically (enableVcEof eof)
          where
            loop i = do
                einp <- getInput' req
                case einp of
                    Left emsg -> logLn env Log.WARN $ "h3-srv: decode-error: " ++ emsg
                    Right ("", True)  -> pure ()
                    Right (bs, _) -> step i bs *> loop (succ i)
            step i bs = do
                atomically (addVcPending pendings i)
                let inp = Input bs i mysa peerInfo DOH toSender
                incStatsDoH3 peersa (stats_ env)
                toCacher inp

        sender = loop `E.catch` onError
          where
            onError (E.SomeException e) = logLn env Log.WARN ("h3-srv: exception: " ++ show e) *> E.throwIO e
            loop = do
                avail <- atomically (waitVcAvail eof pendings availX)
                when avail $ step *> loop
            step = do
                let body (Output bs' _ _) = do
                        let header = mkHeader bs'
                            response = H2.responseBuilder HT.ok200 header $ byteString bs'
                        sendResponse response []
                    finalize (Output _ i _) = atomically (delVcPending pendings i)
                E.bracket fromX finalize body
    TStat.concurrently_ "h3-send" sender "h3-recv" receiver
    logLn env Log.DEBUG $ "h3-srv: close: " ++ show peersa
  where
    -- fixme record
    mkHeader bs =
        [ (HT.hContentType, "application/dns-message")
        , (HT.hContentLength, C8.pack $ show $ C8.length bs)
        ]
