{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.TimeCache (
    TimeCache (..),
    newTimeCache,
    noneTimeCache,
) where

-- GHC packages
import qualified Data.ByteString.Char8 as C8
import Foreign.C.Types (CTime (..))

-- other packages
import Data.UnixTime (UnixTime (..), formatUnixTime, getUnixTime)

-- dnsext-* packages
import DNS.Types.Time (EpochTime)

-- this package
import DNS.Utils.AutoUpdate (mkClosableAutoUpdate)

{- FOURMOLU_DISABLE -}
data TimeCache = TimeCache
    { getTime         :: IO EpochTime
    , getTimeStr      :: IO ShowS
    , closeTimeCache  :: IO ()
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
newTimeCache :: IO TimeCache
newTimeCache = do
    let interval = 1_000_000
    (onceGetString, close) <- mkClosableAutoUpdate interval (getTimeShowS =<< getUnixTime)
    {- Due to the efficient time retrieval enabled by the vdso(7) mechanism, caching is not required.
       Only the formatting of time strings is subject to caching.
       https://man7.org/linux/man-pages/man7/vdso.7.html -}
    return $ TimeCache (unixToEpoch <$> getUnixTime) onceGetString close
{- FOURMOLU_ENABLE -}

noneTimeCache :: TimeCache
noneTimeCache =
    TimeCache
        { getTime = unixToEpoch <$> getUnixTime
        , getTimeStr = getTimeShowS =<< getUnixTime
        , closeTimeCache = pure ()
        }

---

getTimeShowS :: UnixTime -> IO ShowS
getTimeShowS ts = (++) . C8.unpack <$> formatUnixTime "%Y-%m-%dT%H:%M:%S%z" ts

unixToEpoch :: UnixTime -> EpochTime
unixToEpoch (UnixTime (CTime tim) _) = tim
