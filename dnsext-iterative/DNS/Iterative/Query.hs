module DNS.Iterative.Query (
    -- * Env, Types
    module DNS.Iterative.Query.Env,
    module DNS.Iterative.Query.Types,

    -- * Iterative query
    resolveResponseIterative,
    foldResponseIterative,
    foldResponseIterative',

    -- * Cache
    foldResponseCached,
) where

-- dnsext-types
import DNS.Types

-- dnsext-utils
import DNS.WorkerStats (noopWorkerStat)

-- dnsext-do53
import DNS.Do53.Client

-- this package
import DNS.Iterative.Query.API
import DNS.Iterative.Query.Env
import DNS.Iterative.Query.Types (VResult (..))

resolveResponseIterative :: Env -> Question -> QueryControls -> IO (Either String DNSMessage)
resolveResponseIterative env q ictl = foldResponseIterative' Left (\_ -> Right) env noopWorkerStat 0 {- dummy id -} q ictl
