{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Env (
    Env (..),
    newEnv,
    newEmptyEnv,
) where

-- GHC packages
import Data.IORef (newIORef)
import System.Timeout (timeout)

-- other packages

-- dnsext packages
import DNS.Do53.Client (Reply)
import DNS.Do53.Internal (newConcurrentGenId)
import qualified DNS.Log as Log
import DNS.RRCache (RRCacheOps (..))
import qualified DNS.RRCache as Cache
import qualified DNS.TAP.Schema as DNSTAP
import DNS.TimeCache (TimeCache (..), noneTimeCache)

-- this package
import DNS.Iterative.Query.Types
import DNS.Iterative.Stats

{- FOURMOLU_DISABLE -}
-- | Creating a new 'Env'.
newEnv
    :: Log.PutLines
    -> (DNSTAP.Message -> IO ())
    -> Bool
    -- ^ disabling IPv6
    -> RRCacheOps
    -> TimeCache
    -> (IO Reply -> IO (Maybe Reply))
    -> IO Env
newEnv putLines putDNSTAP disableV6NS RRCacheOps{..} TimeCache{..} tmout = do
    env0 <- newEmptyEnv
    pure $
        env0
        { logLines_ = putLines
        , logDNSTAP_ = putDNSTAP
        , disableV6NS_ = disableV6NS
        , insert_ = insertCache
        , getCache_ = readCache
        , expireCache_ = expireCache
        -- , currentRoot_ = <default>
        , currentSeconds_ = getTime
        , timeString_ = getTimeStr
        -- , idGen_ = <default>
        -- , stats_ = <default>
        , timeout_ = tmout
        }

newEmptyEnv :: IO Env
newEmptyEnv = do
    genId    <- newConcurrentGenId
    rootRef  <- newIORef Nothing
    stats <- newStats
    let TimeCache {..} = noneTimeCache
    pure $
        Env
        { logLines_ = \_ _ ~_ -> pure ()
        , logDNSTAP_ = \_ -> pure ()
        , disableV6NS_ = False
        , insert_ = \_ _ _ _ -> pure ()
        , getCache_ = pure $ Cache.empty 0
        , expireCache_ = \_ -> pure ()
        , currentRoot_ = rootRef
        , currentSeconds_ = getTime
        , timeString_ = getTimeStr
        , idGen_ = genId
        , stats_ = stats
        , timeout_ = timeout 5000000
        }
{- FOURMOLU_ENABLE -}
