{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP2 (
    http2Servers,
    http2cServers,
    VcServerConfig (..),
    getInput,
) where

-- GHC packages
import Control.Monad (forever)
import Data.ByteString.Builder (byteString)
import Data.Functor
import qualified Data.ByteString.Char8 as C8

-- dnsext-* packages
import DNS.Do53.Internal
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import Data.ByteString.Base64.URL
import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import Network.HTTP2.TLS.Server (ServerIO (..))
import qualified Network.HTTP2.TLS.Server as H2TLS

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsDoH2, incStatsDoH2C, sessionStatsDoH2, sessionStatsDoH2C)

http2Servers :: VcServerConfig -> ServerActions
http2Servers conf env toCacher ss =
    concat <$> mapM (http2Server conf env toCacher) ss

http2Server :: VcServerConfig -> Env -> ToCacher -> Socket -> IO ([IO ()])
http2Server VcServerConfig{..} env toCacher s = do
    name <- socketName s <&> (++ "/h2")
    let http2server = withLocationIOE name $ H2TLS.runIO settings vc_credentials s $ doHTTP "h2" sbracket incQuery env toCacher
    return [http2server]
  where
    sbracket = sessionStatsDoH2 (stats_ env)
    incQuery inet6 = incStatsDoH2 inet6 (stats_ env)
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
            , H2TLS.settingsSessionManager = vc_session_manager
            , H2TLS.settingsEarlyDataSize = vc_early_data_size
            }

http2cServers :: VcServerConfig -> ServerActions
http2cServers conf env toCacher ss =
    concat <$> mapM (http2cServer conf env toCacher) ss

http2cServer :: VcServerConfig -> Env -> ToCacher -> Socket -> IO ([IO ()])
http2cServer VcServerConfig{..} env toCacher s = do
    name <- socketName s <&> (++ "/h2c")
    let http2server = withLocationIOE name $ H2TLS.runIOH2C settings s $ doHTTP "h2c" sbracket incQuery env toCacher
    return [http2server]
  where
    sbracket = sessionStatsDoH2C (stats_ env)
    incQuery inet6 = incStatsDoH2C inet6 (stats_ env)
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
            , H2TLS.settingsSessionManager = vc_session_manager -- not used
            }

doHTTP
    :: String -> (IO () -> IO ()) -> (SockAddr -> IO ()) -> Env -> ToCacher -> ServerIO -> IO (IO ())
doHTTP name sbracket incQuery env toCacher ServerIO{..} = do
    (toSender, fromX, _) <- mkConnector
    let receiver = forever $ do
            (_, strm, req) <- sioReadRequest
            ts <- currentTimestamp_ env
            let peerInfo = PeerInfoH2 sioPeerSockAddr strm
            einp <- getInput req
            case einp of
                Left emsg -> logLn env Log.WARN $ "decode-error: " ++ emsg
                Right bs -> do
                    let inp = Input bs 0 sioMySockAddr peerInfo DOH toSender ts
                    incQuery sioPeerSockAddr
                    toCacher inp
        sender = forever $ do
            Output bs' _ (PeerInfoH2 _ strm) _ts <- fromX
            let header = mkHeader bs'
                response = H2.responseBuilder HT.ok200 header $ byteString bs'
            sioWriteResponse strm response
    return $ sbracket $ TStat.concurrently_ (name ++ "-send") sender (name ++ "-recv") receiver
  where
    mkHeader bs =
        [ (HT.hContentType, "application/dns-message")
        , (HT.hContentLength, C8.pack $ show $ C8.length bs)
        ]

getInput :: H2.Request -> IO (Either String C8.ByteString)
getInput req
    | method == Just "GET" = case H2.requestPath req of
        Just path | "/dns-query?dns=" `C8.isPrefixOf` path -> return $ Right $ decodeBase64Lenient $ C8.drop 15 path
        _ -> return $ Left "illegal URL"
    | method == Just "POST" = do
        (_rx, rqs) <- recvManyN (H2.getRequestBodyChunk req) 2048
        return $ Right $ C8.concat rqs
    | otherwise = return $ Left "illegal method"
  where
    method = H2.requestMethod req
