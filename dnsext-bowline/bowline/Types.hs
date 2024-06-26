module Types where

import Control.Concurrent.STM
import Data.ByteString.Builder
import Data.IORef

--
import DNS.Types

{- FOURMOLU_DISABLE -}
data CacheControl =
    CacheControl
    { ccRemove          :: Domain -> IO ()
    , ccRemoveType      :: Domain -> TYPE -> IO ()
    , ccRemoveBogus     :: IO ()
    , ccRemoveNegative  :: IO ()
    , ccClear           :: IO ()
    }
{- FOURMOLU_ENABLE -}

data Command = Quit | Reload | KeepCache

data Control = Control
    { getStats :: IO Builder
    , getWStats :: IO Builder
    , cacheControl :: CacheControl
    , quitServer :: IO ()
    , waitQuit :: STM ()
    , getCommandAndClear :: IO Command
    , setCommand :: Command -> IO ()
    }

emptyCacheControl :: CacheControl
emptyCacheControl = CacheControl (\_ -> pure ()) (\_ _ -> pure ()) (pure ()) (pure ()) (pure ())

newControl :: IO Control
newControl = do
    ref <- newIORef Quit
    return
        Control
            { getStats = return mempty
            , getWStats = return mempty
            , quitServer = return ()
            , cacheControl = emptyCacheControl
            , waitQuit = return ()
            , getCommandAndClear = atomicModifyIORef' ref (\x -> (Quit, x))
            , setCommand = atomicWriteIORef ref
            }
