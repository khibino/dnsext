module DNS.Cache.Iterative.Env (
    newEnv,
    getUpdateCache,
) where

-- GHC packages
import Data.IORef (newIORef)

-- other packages

-- dns packages

import DNS.Do53.Internal (
    newConcurrentGenId,
 )
import qualified DNS.Do53.Memo as Cache

-- this package
import DNS.Cache.Iterative.Types
import qualified DNS.Log as Log

getUpdateCache :: Cache.MemoConf -> IO UpdateCache
getUpdateCache cacheConf = do
    memo <- Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
        expire now = Cache.expiresMemo now memo
        read' = Cache.readMemo memo
    return (insert, read', expire)

-- | Creating a new 'Env'.
newEnv
    :: (Log.PutLines, Log.GetQueueSize, Log.Terminate)
    -> Bool
    -- ^ disabling IPv6
    -> UpdateCache
    -> TimeCache
    -> IO Env
newEnv (putLines, getQSize, terminate) disableV6NS (ins, getCache, expire) (curSec, timeStr) = do
    genId <- newConcurrentGenId
    rootRef <- newIORef Nothing
    let cxt =
            Env
                { logLines_ = putLines
                , logQSize_ = getQSize
                , logTerminate_ = terminate
                , disableV6NS_ = disableV6NS
                , insert_ = ins
                , getCache_ = getCache
                , expireCache = expire
                , currentRoot_ = rootRef
                , currentSeconds_ = curSec
                , timeString_ = timeStr
                , idGen_ = genId
                }
    return cxt