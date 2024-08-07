module DNS.Iterative.Server.Types (
    ServerActions,
    Env,
    VcServerConfig (..),
    ToCacher,
    FromReceiver,
    ToWorker,
    FromCacher,
    ToSender,
    FromX,
    ReqNum,
    Input (..),
    Output (..),
    PeerInfo (..),
    Timestamp,
    peerSockAddr,
    withLocationIOE,
    Socket,
    SockAddr (..),
    withFdSocket,
    socketName,
) where

-- GHC
import Data.ByteString (ByteString)
import System.IO.Error (ioeSetLocation, tryIOError)

-- libs
import Data.IP (fromSockAddr)
import qualified Network.HTTP2.Server.Internal as H2I
import qualified Network.QUIC as QUIC
import Network.Socket
import Network.TLS (Credentials (..), SessionManager)

-- dnsext
import DNS.TAP.Schema (SocketProtocol)
import DNS.TimeCache (Timestamp)
import DNS.Types (DNSMessage)

-- this package
import DNS.Iterative.Query (Env)

data PeerInfo
    = PeerInfoUDP SockAddr [Cmsg]
    | PeerInfoQUIC SockAddr QUIC.Stream
    | PeerInfoH2 SockAddr H2I.Stream
    | PeerInfoVC SockAddr
    deriving (Show)

peerSockAddr :: PeerInfo -> SockAddr
peerSockAddr (PeerInfoUDP sa _) = sa
peerSockAddr (PeerInfoQUIC sa _) = sa
peerSockAddr (PeerInfoH2 sa _) = sa
peerSockAddr (PeerInfoVC sa) = sa

-- request identifier in one connection
type ReqNum = Int

data Input a = Input
    { inputQuery :: a
    , inputRequestNum :: ReqNum
    , inputMysa :: SockAddr
    , inputPeerInfo :: PeerInfo
    , inputProto :: SocketProtocol
    , inputToSender :: ToSender
    , inputRecvTime :: Timestamp
    }

data Output = Output
    { outputReplyBS :: ByteString
    , outputRequestNum :: ReqNum
    , outputPeerInfo :: PeerInfo
    , outputRecvTime :: Timestamp
    }

type ToCacher = Input ByteString -> IO ()
type FromReceiver = IO (Input ByteString)
type ToWorker = Input DNSMessage -> IO ()
type FromCacher = IO (Input DNSMessage)
type ToSender = Output -> IO ()
type FromX = IO Output

type ServerActions = Env -> ToCacher -> [Socket] -> IO ([IO ()])

data VcServerConfig = VcServerConfig
    { vc_query_max_size :: Int
    , vc_idle_timeout :: Int
    , vc_slowloris_size :: Int
    , vc_credentials :: Credentials
    , vc_session_manager :: SessionManager
    , vc_early_data_size :: Int
    , vc_interface_automatic :: Bool
    }

withLocationIOE :: String -> IO a -> IO a
withLocationIOE loc action = do
    either left pure =<< tryIOError action
  where
    left ioe = ioError $ ioeSetLocation ioe loc

socketName :: Socket -> IO String
socketName s = do
    sa <- getSocketName s
    return $ case fromSockAddr sa of
        Nothing -> "(no name)"
        Just (ip, pn) -> show ip ++ "#" ++ show pn
