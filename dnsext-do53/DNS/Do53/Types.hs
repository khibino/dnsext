{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

-- | Resolver related data types.
module DNS.Do53.Types (
    -- * Configuration for resolver
    LookupConf (..),
    defaultLookupConf,
    UDPRetry,
    VCLimit (unVCLimit),
    LookupEnv (..),

    -- ** Specifying DNS servers
    Seeds (..),

    -- ** Configuring cache
    CacheConf (..),
    defaultCacheConf,

    -- * Type and function for resolver
    ResolveEnv (..),
    ResolveInfo (..),
    defaultResolveInfo,
    ResolveActions (..),
    defaultResolveActions,
    NameTag (..),
    Reply (..),
    Resolver,
    OneshotResolver,
    PipelineResolver,
    PersistentResolver,

    -- * IO
    Recv,
    Recv_,
    RecvN,
    RecvMany,
    RecvManyN,
    RecvManyN_,
    Send,
    SendMany,
)
where

import Data.IP
#ifdef mingw32_HOST_OS
import Network.Socket (setSocketOption, SocketOption(..))
#endif
import Prelude

import DNS.Do53.Id
import DNS.Do53.Imports
import DNS.Do53.Query
import DNS.Log (PutLines)
import DNS.RRCache
import DNS.Types

----------------------------------------------------------------

-- | The type to specify a cache server.
data Seeds
    = -- | A path for \"resolv.conf\"
      -- where one or more IP addresses
      -- of DNS servers should be found
      -- on Unix.
      -- Default DNS servers are
      -- automatically detected
      -- on Windows regardless of
      -- the value of the file name.
      SeedsFilePath FilePath
    | -- | A numeric IP address.
      SeedsAddr IP
    | -- | Numeric IP addresses.
      SeedsAddrs [IP]
    | -- | A numeric IP address and port number.
      SeedsAddrPort IP PortNumber
    | SeedsAddrPorts [(IP, PortNumber)]
    deriving (Show)

----------------------------------------------------------------

-- | Cache configuration for responses.
data CacheConf = CacheConf
    { maximumTTL :: TTL
    -- ^ If RR's TTL is higher than this value, this value is used instead.
    , minimumTTL :: TTL
    -- ^ If RR's TTL is lower than this value, this value is used instead.
    , pruningDelay :: Int
    -- ^ Cache pruning interval in seconds.
    }
    deriving (Show)

-- | Default cache configuration.
--
-- >>> defaultCacheConf
-- CacheConf {maximumTTL = 300(5 mins), minimumTTL = 0(secs), pruningDelay = 10}
defaultCacheConf :: CacheConf
defaultCacheConf = CacheConf 300 0 10

----------------------------------------------------------------

newtype UDPRetry = UDPRetry Int deriving (Eq, Num, Show)

newtype VCLimit = VCLimit {unVCLimit :: Int} deriving (Eq, Ord, Num, Show)

-- | Type for resolver configuration.
--  Use 'defaultLookupConf' to create a new value.
--
--  An example to use Google's public DNS cache instead of resolv.conf:
--
--  > let conf = defaultLookupConf { lconfInfo = RCAddr "8.8.8.8" }
--
--  An example to use multiple Google's public DNS cache concurrently:
--
--  > let conf = defaultLookupConf { lconfInfo = RCAddrs ["8.8.8.8","8.8.4.4"], lconfConcurrent = True }
--
--  An example to disable EDNS:
--
--  > let conf = defaultLookupConf { lconfQueryControls = ednsEnabled FlagClear }
--
--  An example to enable query result caching:
--
--  > let conf = defaultLookupConf { lconfCache = Just defaultCacheConf }
--
-- An example to disable requesting recursive service.
--
--  > let conf = defaultLookupConf { lconfQueryControls = rdFlag FlagClear }
--
-- An example to set the AD bit in all queries by default.
--
--  > let conf = defaultLookupConf { lconfQueryControls = adFlag FlagSet }
--
-- An example to set the both the AD and CD bits in all queries by default.
--
--  > let conf = defaultLookupConf { lconfQueryControls = adFlag FlagSet <> cdFlag FlagSet }
--
-- An example with an EDNS buffer size of 1216 bytes, which is more robust with
-- IPv6, and the DO bit set to request DNSSEC responses.
--
--  > let conf = defaultLookupConf { lconfQueryControls = ednsSetUdpSize (Just 1216) <> doFlag FlagSet }
data LookupConf = LookupConf
    { lconfSeeds :: Seeds
    -- ^ Server information.
    , lconfUDPRetry :: UDPRetry
    -- ^ The number of UDP retries including the first try.
    , lconfVCLimit :: VCLimit
    -- ^ How many bytes are allowed to be received on a virtual circuit.
    , lconfConcurrent :: Bool
    -- ^ Concurrent queries if multiple DNS servers are specified.
    , lconfCacheConf :: Maybe CacheConf
    -- ^ Cache configuration.
    , lconfQueryControls :: QueryControls
    -- ^ Overrides for the default flags used for queries via resolvers that use
    -- this configuration.
    , lconfActions :: ResolveActions
    -- ^ Actions for resolvers.
    }

-- | Return a default 'LookupConf':
--
-- * 'lconfSeeds' is 'SeedsFilePath' \"\/etc\/resolv.conf\".
-- * 'lconfRetry' is 3.
-- * 'lconfConcurrent' is False.
-- * 'lconfCacheConf' is Nothing.
-- * 'lconfQueryControls' is an empty set of overrides.
defaultLookupConf :: LookupConf
defaultLookupConf =
    LookupConf
        { lconfSeeds = SeedsFilePath "/etc/resolv.conf"
        , lconfUDPRetry = 3
        , lconfVCLimit = 8 * 1024
        , lconfConcurrent = False
        , lconfCacheConf = Nothing
        , lconfQueryControls = mempty
        , lconfActions = defaultResolveActions
        }

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver.
--   This includes newly seeded identifier generators for all
--   specified DNS servers and a cache database.
data LookupEnv = LookupEnv
    { lenvCache :: Maybe (RRCache, CacheConf)
    , lenvQueryControls :: QueryControls
    , lenvConcurrent :: Bool
    , lenvResolveEnv :: ResolveEnv
    , lenvActions :: ResolveActions -- for cache lookup
    }

data ResolveEnv = ResolveEnv
    { renvResolver :: OneshotResolver
    , renvConcurrent :: Bool
    , renvResolveInfos :: NonEmpty ResolveInfo
    }

instance Show ResolveEnv where
    show ResolveEnv{..} = "ResolveEnv {" ++ show renvResolveInfos ++ "}"

----------------------------------------------------------------

-- | Information for resolvers.
data ResolveInfo = ResolveInfo
    { rinfoIP :: IP
    , rinfoPort :: PortNumber
    , rinfoActions :: ResolveActions
    , rinfoUDPRetry :: UDPRetry
    , rinfoVCLimit :: VCLimit
    , rinfoPath :: Maybe ShortByteString
    }
    deriving (Show)

defaultResolveInfo :: ResolveInfo
defaultResolveInfo =
    ResolveInfo
        { rinfoIP = "127.0.0.1"
        , rinfoPort = 53
        , rinfoActions = defaultResolveActions
        , rinfoUDPRetry = 3
        , rinfoVCLimit = 2048
        , rinfoPath = Nothing
        }

data Reply = Reply
    { replyTag :: NameTag
    , replyDNSMessage :: DNSMessage
    , replyTxBytes :: Int
    , replyRxBytes :: Int
    }
    deriving (Eq, Show)

-- | The resolver type to send a question and receive a result.
--   Exceptions are not thrown.
type Resolver = Question -> QueryControls -> IO (Either DNSError Reply)

-- | Concurrent resolver which can be shared by multiple threads.
--   'DNSError' is thrown.
type PipelineResolver = (Resolver -> IO ()) -> IO ()

-- | Resolver whose connection is persistent.
type PersistentResolver = ResolveInfo -> PipelineResolver

-- | Resolver whose connection is established on the fly and send a
-- question only once.
type OneshotResolver = ResolveInfo -> Resolver

----------------------------------------------------------------

newtype NameTag = NameTag {unNameTag :: String} deriving (Eq, Ord, Show)

data ResolveActions = ResolveActions
    { ractionTimeoutTime :: Int
    -- ^ Time of timeout in microseconds.
    , ractionGenId :: IO Identifier
    -- ^ Generating identifiers.
    , ractionGetTime :: IO EpochTime
    -- ^ Getting time.
    , ractionSetSockOpt :: Socket -> IO ()
    -- ^ Setting socket options.
    , ractionLog :: PutLines
    -- ^ Logging.
    , ractionShortLog :: Bool
    -- ^ flag for short-log mode
    , ractionKeyLog :: String -> IO ()
    -- ^ Logging for TLS main secrets.
    , ractionResumptionInfo :: NameTag -> [ByteString]
    -- ^ Resumption information for this connection.
    , ractionOnResumptionInfo :: NameTag -> ByteString -> IO ()
    -- ^ Action to store resumption information for next connection.
    , ractionUseEarlyData :: Bool
    -- ^ Use 0-RTT or not.
    , ractionOnConnectionInfo :: NameTag -> String -> IO ()
    -- ^ Action for connection information
    }

instance Show ResolveActions where
    show ResolveActions{..} = "ResolveActions { ractionTimeoutTime = " ++ show ractionTimeoutTime ++ "}"

defaultResolveActions :: ResolveActions
defaultResolveActions =
    ResolveActions
        { ractionTimeoutTime = 3000000
        , ractionGenId = singleGenId
        , ractionGetTime = getEpochTime
        , ractionSetSockOpt = rsso
        , ractionLog = \_ _ ~_ -> return ()
        , ractionShortLog = False
        , ractionKeyLog = \ ~_ -> return ()
        , ractionResumptionInfo = \_ -> []
        , ractionOnResumptionInfo = \_ _ -> return ()
        , ractionUseEarlyData = False
        , ractionOnConnectionInfo = \_ _ -> return ()
        }

rsso :: Socket -> IO ()
#ifdef mingw32_HOST_OS
rsso sock = setSocketOption sock RecvTimeOut 3000000
#else
rsso _ = return ()
#endif

----------------------------------------------------------------

type Recv = Recv_ ByteString

type Recv_ = IO

type RecvN = Int -> IO ByteString

type RecvMany = IO (Int, [ByteString])

type RecvManyN = RecvManyN_ ByteString

type RecvManyN_ a = Int -> IO (Int, [a])

type Send = ByteString -> IO ()

type SendMany = [ByteString] -> IO ()
