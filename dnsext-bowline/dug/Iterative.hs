{-# LANGUAGE RecordWildCards #-}

module Iterative (iterativeQuery) where

import DNS.Do53.Client (QueryControls)
import DNS.Iterative.Query (Env, resolveResponseIterative, newEnv)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import DNS.TimeCache (TimeCache (..), newTimeCache)
import Data.String (fromString)
import Network.Socket (HostName)

import DNS.Types

iterativeQuery
    :: Bool
    -> Log.PutLines
    -> QueryControls
    -> HostName
    -> TYPE
    -> IO (Either String DNSMessage)
iterativeQuery disableV6NS putLines ctl domain typ = do
    env <- setup disableV6NS putLines
    resolve env ctl domain typ

setup :: Bool -> Log.PutLines -> IO Env
setup disableV6NS putLines = do
    tcache@TimeCache{..} <- newTimeCache
    let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 getTime
    cacheOps <- Cache.newRRCacheOps cacheConf
    newEnv putLines (\_ -> return ()) disableV6NS cacheOps tcache

resolve
    :: Env -> QueryControls -> String -> TYPE -> IO (Either String DNSMessage)
resolve env ictl n ty = resolveResponseIterative env domain ty ictl
  where
    domain = fromString n
