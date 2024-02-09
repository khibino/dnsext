module SocketUtil (
    addrInfo,
    ainfosSkipError,
    ainfoSkipError,
    mkSocketWaitForByte,
    isAnySockAddr,
) where

-- GHC internal packages
import GHC.IO.Device (IODevice (ready))
import GHC.IO.FD (mkFD)
import Data.Functor

-- GHC packages
import System.IO (IOMode (ReadMode))
import System.IO.Error (tryIOError)

-- dns packages
import Network.Socket (
    AddrInfo (..),
    HostName,
    NameInfoFlag (..),
    PortNumber,
    ServiceName,
    SockAddr (..),
    Socket,
    SocketType,
 )
import qualified Network.Socket as S

addrInfo :: PortNumber -> [HostName] -> IO [AddrInfo]
addrInfo p [] = S.getAddrInfo Nothing Nothing $ Just $ show p
addrInfo p hs@(_ : _) =
    concat <$> sequence [S.getAddrInfo Nothing (Just h) $ Just $ show p | h <- hs]

ainfosSkipError :: (String -> IO ()) -> SocketType -> PortNumber -> [HostName] -> IO [(AddrInfo, HostName, ServiceName)]
ainfosSkipError logLn sty p [] = ainfoSkipError logLn sty Nothing p
ainfosSkipError logLn sty p hs@(_ : _) =
    concat <$> sequence [ainfoSkipError logLn sty (Just h) p | h <- hs]

{- FOURMOLU_DISABLE -}
ainfoSkipError :: (String -> IO ()) -> SocketType -> Maybe HostName -> PortNumber -> IO [(AddrInfo, HostName, ServiceName)]
ainfoSkipError logLn socktype mhost port =
    either left right =<< tryIOError (S.getAddrInfo Nothing mhost (Just $ show port))
  where
    left e = logLn (unwords ["skipping", (maybe "*" show mhost) ++ ":" ++ show port, show socktype, ":", show e]) $> []
    right as = take 1 . concat <$> mapM inet as
    inet ai
        | addrSocketType ai == socktype  = maybe [] (:[]) <$> ainfoInetAddr ai
        | otherwise                      = pure []
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
ainfoInetAddr :: AddrInfo -> IO (Maybe (AddrInfo, HostName, ServiceName))
ainfoInetAddr ai = do
    (mhost, mport) <- S.getNameInfo [NI_NUMERICHOST, NI_NUMERICSERV] True True $ addrAddress ai
    pure $ do host <- mhost
              port <- mport
              Just (ai, host, port)
{- FOURMOLU_ENABLE -}

{- make action to wait for socket-input from cached FD
   without calling fdStat and mkFD for every wait-for calls -}
mkSocketWaitForByte :: Socket -> IO (Int -> IO Bool)
mkSocketWaitForByte sock =
    withFD <$> S.withFdSocket sock getFD
  where
    withFD fd millisec =
        ready fd False millisec
    getFD fd =
        fst
            <$> mkFD
                fd
                ReadMode
                Nothing {- stat, filled in `mkFD`, calling `fdStat` -}
                False {- socket flag for only Windows -}
                False {- non-blocking, False -}
                {-
                mkSocketWaitForInput sock =
                  withStat <$> withFdSocket sock fdStat
                  where
                    withStat stat millisec = do
                      (fd, _) <- withFdSocket sock $ getFD stat
                      ready fd False millisec
                    getFD stat fd =
                      mkFD fd ReadMode
                      (Just stat)  {- stat, get from `fdStat` -}
                      False        {- socket flag for only Windows -}
                      False        {- non-blocking, False -}

                -- import System.Posix.Internals (fdStat)
                -}

isAnySockAddr :: SockAddr -> Bool
isAnySockAddr (SockAddrInet _ 0) = True
isAnySockAddr (SockAddrInet6 _ _ (0, 0, 0, 0) _) = True
isAnySockAddr _ = False
