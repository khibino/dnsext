module DNS.Cache.Iterative.Norec (norec) where

-- GHC packages
import qualified Control.Exception as E
import Control.Monad.Trans.Except (ExceptT (..))
import Control.Monad.Trans.Reader (ReaderT (..))

-- other packages

-- dns packages

import DNS.Do53.Client (
    FlagOp (..),
    QueryControls (..),
    defaultResolvActions,
    ractionGenId,
    ractionGetTime,
    ractionLog,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    ResolvEnv (..),
    ResolvInfo (..),
    defaultResolvInfo,
    udpTcpResolver,
 )
import qualified DNS.Do53.Internal as DNS
import DNS.SEC (
    TYPE,
 )
import DNS.Types (
    DNSMessage,
    Domain,
    Question (..),
    classIN,
 )
import qualified DNS.Types as DNS
import Data.IP (IP)

-- this package
import DNS.Cache.Iterative.Types

{- Get the answer DNSMessage from the authoritative server.
   Note about flags in request to an authoritative server.
  * RD (Recursion Desired) must be 0 for request to authoritative server
  * EDNS must be enable for DNSSEC OK request -}
norec :: Bool -> [IP] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnsssecOK aservers name typ = dnsQueryT $ \cxt _qctl -> do
    let ris =
            [ defaultResolvInfo
                { rinfoHostName = show aserver
                , rinfoActions =
                    defaultResolvActions
                        { ractionGenId = idGen_ cxt
                        , ractionGetTime = currentSeconds_ cxt
                        , ractionLog = logLines_ cxt
                        }
                }
            | aserver <- aservers
            ]
        renv =
            ResolvEnv
                { renvResolver = udpTcpResolver 3 (32 * 1024) -- 3 is retry
                , renvConcurrent = True -- should set True if multiple RIs are provided
                , renvResolvInfos = ris
                }
        q = Question name typ classIN
        doFlagSet
            | dnsssecOK = FlagSet
            | otherwise = FlagClear
        qctl = DNS.rdFlag FlagClear <> DNS.doFlag doFlagSet
    either
        (Left . DnsError)
        ( \res -> handleResponseError Left Right $ DNS.replyDNSMessage (DNS.resultReply res)
        )
        <$> E.try (DNS.resolve renv q qctl)

handleResponseError :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError e f msg
    | DNS.qOrR flags /= DNS.QR_Response = e $ NotResponse (DNS.qOrR flags) msg
    | DNS.ednsHeader msg == DNS.InvalidEDNS =
        e $ InvalidEDNS (DNS.ednsHeader msg) msg
    | DNS.rcode flags
        `notElem` [DNS.NoErr, DNS.NameErr] =
        e $ HasError (DNS.rcode flags) msg
    | otherwise = f msg
  where
    flags = DNS.flags $ DNS.header msg

dnsQueryT
    :: (Env -> QueryControls -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT k = ExceptT $ ReaderT $ ReaderT . k