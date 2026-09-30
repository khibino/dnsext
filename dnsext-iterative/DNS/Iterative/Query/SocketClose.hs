
module DNS.Iterative.Query.SocketClose where

-- GHC
import Control.Monad
import GHC.Conc (closeFdWith)
import System.Posix.Types (Fd)
import Foreign.C.Types

-- network
import Network.Socket (Socket)
import Network.Socket.Internal (invalidateSocket)

withClose :: (Fd -> IO ()) -> Socket -> IO ()
withClose closeFd_ s = invalidateSocket s (\_ -> return ()) $ \oldfd -> do
    -- closeFdWith avoids the deadlock of IO manager.
    closeFdWith closeFd_ (toFd oldfd)
  where
    toFd :: CInt -> Fd
    toFd = fromIntegral

closeFd :: Fd -> IO ()
closeFd = void . c_close . fromIntegral

foreign import ccall unsafe "close"
  c_close :: CInt -> IO CInt
