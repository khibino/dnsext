module DNS.Iterative.Query (
    -- * Env, Types
    module DNS.Iterative.Query.Env,
    module DNS.Iterative.Query.Types,

    -- * Iterative query
    resolveResponseIterative,
    foldResponseIterative64,
    foldResponseIterative,
    foldResponseIterative',

    -- * Cache
    foldResponseCached64,
    foldResponseCached,
) where

-- dnsext-types
import DNS.Types

-- dnsext-utils
import DNS.WorkerStats (noopWorkerStat)
import DNS.Transport.Types (Synthesis (..))

-- dnsext-do53
import DNS.Do53.Client

-- this package
import DNS.Iterative.Query.API
import DNS.Iterative.Query.Env
import DNS.Iterative.Query.Types (DNSQuery, FoldResponse, VResult (..))


resolveResponseIterative :: Env -> Synthesis -> Question -> QueryControls -> IO (Either String DNSMessage)
resolveResponseIterative env syn q ictl = foldIterative syn Left (\_ -> Right) env noopWorkerStat 0 {- dummy id -} q ictl
  where
    foldIterative SynthDNS64  = foldResponseIterative64'
    foldIterative SynthNone   = foldResponseIterative'
