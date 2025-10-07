{-# LANGUAGE MonadComprehensions #-}
{-# LANGUAGE NumericUnderscores #-}

module DNS.Iterative.Query.Norec where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (
    FlagOp (..),
    ResolveActions (..),
    defaultResolveActions,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    ResolveEnv (..),
    ResolveInfo (..),
    defaultResolveInfo,
    udpTcpResolver,
 )
import qualified DNS.Do53.Internal as DNS
import DNS.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Class

norec' :: MonadEnv m => Bool -> NonEmpty Address -> Domain -> TYPE -> m (Either DNSError DNSMessage)
norec' dnssecOK aservers name typ = asksEnv id >>= \env -> norec env dnssecOK aservers name typ

{- FOURMOLU_DISABLE -}
{- Get the answer DNSMessage from the authoritative server.
   Note about flags in request to an authoritative server.
  * RD (Recursion Desired) must be 0 for request to authoritative server
  * EDNS must be enable for DNSSEC OK request -}
norec :: MonadIO m => Env -> Bool -> NonEmpty Address -> Domain -> TYPE -> m (Either DNSError DNSMessage)
norec cxt dnssecOK aservers name typ = do
    let riActions =
            defaultResolveActions
                { ractionGenId        = idGen_ cxt
                , ractionGetTime      = currentSeconds_ cxt
                , ractionLog          = logLines_ cxt
                , ractionShortLog     = shortLog_ cxt
                , ractionTimeoutTime  = 200_000
                }
        ris =
            [ defaultResolveInfo
                { rinfoIP        = aserver
                , rinfoPort      = port
                , rinfoActions   = riActions
                , rinfoUDPRetry  = if length aservers == 1 then 2 else 1
                , rinfoVCLimit   = 8 * 1024
                }
            | (aserver, port) <- aservers
            ]
        renv =
            ResolveEnv
                { renvResolver      = udpTcpResolver
                , renvConcurrent    = True -- should set True if multiple RIs are provided
                , renvResolveInfos  = ris
                }
        q = Question name typ IN
        doFlagSet
            | dnssecOK = FlagSet
            | otherwise = FlagClear
        qctl = DNS.rdFlag FlagClear <> DNS.doFlag doFlagSet
    liftIO $ fmap DNS.replyDNSMessage <$> DNS.resolve renv q qctl
{- FOURMOLU_ENABLE -}
