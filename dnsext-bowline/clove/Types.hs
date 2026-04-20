module Types where

import Data.IORef
import Data.IP
import Data.IP.RouteTable

import DNS.Auth.Algorithm
import DNS.Log
import DNS.Types

----------------------------------------------------------------

data Source
    = FromFile FilePath
    | FromUpstream4 IPv4
    | FromUpstream6 IPv6
    deriving (Eq, Show)

data ZoneConf = ZoneConf
    { cnf_zone :: String
    , cnf_source :: String
    , cnf_dnssec :: Bool
    , cnf_notify :: Bool
    , cnf_notify_addrs :: [String]
    , cnf_allow_notify :: Bool
    , cnf_allow_notify_addrs :: [String]
    , cnf_allow_transfer :: Bool
    , cnf_allow_transfer_addrs :: [String]
    }
    deriving (Show)

----------------------------------------------------------------

type WakeUp = IO ()
type Wait = Int -> IO ()

data Zone = Zone
    { zoneName :: Domain
    , zoneSource :: Source
    , zoneDB :: DB
    , zoneReady :: Bool
    , zoneShouldRefresh :: Bool
    , zoneNotifyAddrs :: [IP]
    , zoneAllowNotifyAddrs :: [IP]
    , zoneAllowTransfer4 :: IPRTable IPv4 Bool
    , zoneAllowTransfer6 :: IPRTable IPv6 Bool
    , zoneWait :: Int -> IO ()
    , zoneWakeUp :: IO ()
    }

type ZoneAlist = [(Domain, IORef Zone)]

----------------------------------------------------------------

data Env = Env
    { envPutLines :: PutLines IO
    }
