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
    VcPendingOp (..),
    DoX (..),
    Input (..),
    Output (..),
    Peer (..),
    EpochTimeUsec,
    peerSockAddr,
    withLocationIOE,
    Socket,
    SockAddr (..),
    withFdSocket,
    loggingTimeout,
    socketName,
    SuperStream (..),
) where

-- GHC
import Data.ByteString (ByteString)
import System.IO.Error (ioeSetLocation, tryIOError)
import System.Timeout

-- libs
import Data.IP (fromSockAddr)
import qualified Network.HTTP2.Server.Internal as H2I
import qualified Network.QUIC as QUIC
import Network.Socket
import Network.TLS (Credentials (..), SessionManager)

-- dnsext
import DNS.Types (DNSMessage)
import DNS.Types.Time (EpochTimeUsec)

-- this package
import DNS.Iterative.Query (Env)

data SuperStream = StreamH2 H2I.Stream | StreamQUIC QUIC.Stream deriving (Show)

data Peer
    = PeerInfoUDP SockAddr [Cmsg]
    | PeerInfoStream SockAddr SuperStream
    | PeerInfoVC SockAddr
    deriving (Show)

peerSockAddr :: Peer -> SockAddr
peerSockAddr (PeerInfoUDP sa _) = sa
peerSockAddr (PeerInfoStream sa _) = sa
peerSockAddr (PeerInfoVC sa) = sa

-- request identifier in one connection
type ReqNum = Int

data VcPendingOp
    = VcPendingOp
    { vpReqNum :: ReqNum
    , vpDelete :: IO ()
    }

data DoX
    = UDP
    | TCP
    | DoT
    | H2
    | H2C
    | H3
    | DoQ
    deriving (Eq, Show)

data Input a = Input
    { inputQuery :: a
    , inputPendingOp :: VcPendingOp
    , inputMysa :: SockAddr
    , inputPeerInfo :: Peer
    , inputDoX :: DoX
    , inputToSender :: ToSender -> IO ()
    , inputRecvTime :: EpochTimeUsec
    }

data Output = Output
    { outputReplyBS :: ByteString
    , outputPendingOp :: VcPendingOp
    , outputPeerInfo :: Peer
    }

-- Type of the action reveals its arguments and the context of the monad,
--   eg.
--   - toCacher :: ToCacher -> IO ()
--   - toSender :: IO ToSender
type ToCacher = Input ByteString
type FromReceiver = Input ByteString
type ToWorker = Input DNSMessage
type FromCacher = Input DNSMessage
type ToSender = Output
type FromX = Output

type ServerActions = Env -> (ToCacher -> IO ()) -> [Socket] -> IO [IO ()]

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

loggingTimeout :: IO () -> Int -> IO () -> IO ()
loggingTimeout logging intv x =
    maybe logging pure =<< timeout intv x
