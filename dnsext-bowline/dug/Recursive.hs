{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Recursive (recursiveQuery) where

import Codec.Serialise
import Control.Concurrent (MVar, newMVar, withMVar)
import Control.Concurrent.Async
import Control.Concurrent.STM
import qualified Control.Exception as E
import Control.Monad
import DNS.Do53.Client (
    LookupConf (..),
    QueryControls,
    ResolveActions (..),
    Seeds (..),
    withLookupConf,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    LookupEnv (..),
    NameTag (..),
    PipelineResolver,
    Reply (..),
    ResolveActions (..),
    ResolveInfo (..),
    defaultResolveActions,
    defaultResolveInfo,
    fromNameTag,
    resolve,
    toNameTag,
 )
import DNS.DoX.Client
import qualified DNS.Log as Log
import DNS.Types (Question (..))
import qualified DNS.Types as DNS
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import Data.Either
import Data.IP (IP (..))
import qualified Data.List as List
import qualified Network.QUIC.Client as QUIC
import Network.Socket (HostName, PortNumber)
import qualified Network.TLS as TLS
import System.Console.ANSI.Types
import System.Directory (doesFileExist, removeFile)
import System.Exit (exitFailure)

import SocketUtil (checkDisableV6)
import Types

recursiveQuery
    :: [(IP, Maybe HostName)]
    -> PortNumber
    -> (DNS.DNSMessage -> STM ())
    -> Log.PutLines STM
    -> [(Question, QueryControls)]
    -> Options
    -> TQueue (NameTag, String)
    -> IO ()
recursiveQuery ips port putLnSTM putLinesSTM qcs opt@Options{..} tq = do
    keyloglock <- newMVar ()
    resumplock <- newMVar ()
    let ractions =
            defaultResolveActions
                { ractionLog = \a b c -> atomically $ putLinesSTM a b c
                , ractionOnResumptionInfo = case optResumptionFile of
                    Nothing -> \_ _ -> return ()
                    Just file -> saveResumption file resumplock tq
                , ractionUseEarlyData = opt0RTT
                , ractionKeyLog = case optKeyLogFile of
                    Nothing -> TLS.defaultKeyLogger
                    Just file -> \msg -> safeAppendFile file keyloglock (C8.pack (msg ++ "\n"))
                , ractionValidate = optValidate
                }
    (conf, aps) <- getCustomConf ips port mempty opt ractions
    mx <-
        if optDoX == "auto"
            then resolvePipeline opt conf tq
            else case makePersistentResolver optDoX of
                -- PersistentResolver
                Just persitResolver -> do
                    mrs <- case optResumptionFile of
                        Nothing -> return []
                        Just file -> do
                            exist <- doesFileExist file
                            if exist
                                then do
                                    ct <- loadResumption file
                                    removeFile file
                                    return ct
                                else return []
                    let ris = makeResolveInfo ractions tq aps mrs
                    -- [PipelineResolver]
                    return $ Just (persitResolver <$> ris)
                Nothing -> return Nothing
    case mx of
        Nothing -> withLookupConf conf $ \LookupEnv{..} -> do
            -- UDP
            let printIt (q, ctl) = resolve lenvResolveEnv q ctl >>= atomically . printReplySTM putLnSTM putLinesSTM
            mapM_ printIt qcs
        Just [] -> do
            putStrLn $ show optDoX ++ " connection cannot be created"
            exitFailure
        Just pipes -> do
            -- VC
            let len = length qcs
            refs <- replicateM len $ newTVarIO False
            let targets = zip qcs refs
            -- raceAny cannot be used to ensure that TLS sessino tickets
            -- are certainly saved.
            rs <- mapConcurrently (E.try . resolver putLnSTM putLinesSTM targets) pipes
            let r@(Right _) `op` _ = r
                _ `op` l = l
            case foldr1 op rs of
                Left e -> do
                    print (e :: DNS.DNSError)
                    exitFailure
                _ -> return ()

resolvePipeline
    :: Options
    -> LookupConf
    -> TQueue (NameTag, String)
    -> IO (Maybe [PipelineResolver])
resolvePipeline Options{..} conf tq = do
    er <- withLookupConf conf lookupSVCBInfo
    case er of
        Left err -> do
            print err
            exitFailure
        Right siss0 -> do
            disableV6 <- checkDisableV6 [rinfoIP ri | sis <- siss0, SVCBInfo{..} <- sis, ri <- svcbInfoResolveInfos]
            let isIPv4 (IPv4 _) = True
                isIPv4 _ = False
                ipv4only si =
                    si
                        { svcbInfoResolveInfos = filter (isIPv4 . rinfoIP) $ svcbInfoResolveInfos si
                        }
            let siss
                    | optDisableV6NS || disableV6 = map (map ipv4only) siss0
                    | otherwise = siss0
            let psss = map toPipelineResolvers $ map (map addAction) siss
            case psss of
                [] -> do
                    putStrLn "No proper SVCB"
                    exitFailure
                pss : _ -> case pss of
                    [] -> do
                        putStrLn "No proper SVCB"
                        exitFailure
                    ps : _ -> return $ Just ps
  where
    addAction si =
        si
            { svcbInfoResolveInfos = map (add si) $ svcbInfoResolveInfos si
            }
    -- RFC 9642 requires the following *designation*:
    --
    --   ipaddr -> SVCB(ipv4hint)
    --   ipv4hint -> SAN(ipaddr)
    --       SNI = None
    --       Host: ipaddr
    add si ri@ResolveInfo{..} =
        ri
            { rinfoActions =
                rinfoActions
                    { ractionOnConnectionInfo = \tag info -> atomically $ writeTQueue tq (tag, info)
                    , -- RFC 9462, Sec 4.2 says:
                      --
                      -- 1. The client MUST verify the chain of certificates
                      --    up to a trust anchor as described in Section 6 of
                      --    [RFC5280].  The client SHOULD use the default
                      --    system or application trust anchors, unless
                      --    otherwise configured.
                      --
                      -- 2. The client MUST verify that the certificate
                      --    contains the IP address of the designating
                      --    Unencrypted DNS Resolver in an iPAddress entry of
                      --    the subjectAltName extension as described in
                      --    Section 4.2.1.6 of [RFC5280].
                      ractionServerAltName = if optValidate then Just $ nameTagIP $ svcbInfoNameTag si else Nothing
                    }
            , -- SEc 6.3 says:
              -- When performing discovery using resolver IP addresses,
              -- clients MUST use the original IP address of the
              -- Unencrypted DNS Resolver as the URI host for DoH
              -- requests.
              rinfoServerName = Just $ show $ nameTagIP $ svcbInfoNameTag si
            }

resolver
    :: (DNS.DNSMessage -> STM ())
    -> Log.PutLines STM
    -> [((Question, QueryControls), TVar Bool)]
    -> PipelineResolver
    -> IO ()
resolver putLnSTM putLinesSTM targets pipeline = pipeline $ \resolv -> do
    -- running concurrently for multiple target domains
    rs <- mapConcurrently (printIt resolv) targets
    case foldr op (Right ()) rs of
        Right () -> return ()
        Left e -> E.throwIO (e :: DNS.DNSError)
  where
    l@(Left _) `op` _ = l
    _ `op` r = r
    printIt resolv ((q, ctl), tvar) = E.try $ do
        er <- resolv q ctl
        atomically $ do
            done <- readTVar tvar
            unless done $ do
                printReplySTM putLnSTM putLinesSTM er
                writeTVar tvar True

printReplySTM
    :: (DNS.DNSMessage -> STM ())
    -> Log.PutLines STM
    -> Either DNS.DNSError Reply
    -> STM ()
printReplySTM _ putLinesSTM (Left err) = putLinesSTM Log.WARN (Just Red) [show err]
printReplySTM putLnSTM putLinesSTM (Right r@Reply{..}) = do
    let h = mkHeader r
    putLinesSTM Log.WARN (Just Green) [h]
    putLnSTM replyDNSMessage

makeResolveInfo
    :: ResolveActions
    -> TQueue (NameTag, String)
    -> [(IP, Maybe HostName, PortNumber)]
    -> [(NameTag, ByteString)]
    -> [ResolveInfo]
makeResolveInfo ractions tq aps ss = mk <$> aps
  where
    mk (ip, msvr, port) =
        defaultResolveInfo
            { rinfoIP = ip
            , rinfoPort = port
            , rinfoUDPRetry = 2
            , rinfoActions = ractions'
            , rinfoVCLimit = 8192
            , rinfoServerName = msvr
            }
      where
        ractions' =
            ractions
                { ractionOnConnectionInfo = \tag info -> atomically $ writeTQueue tq (tag, info)
                , ractionResumptionInfo = \tag -> map snd $ fst $ List.partition (\(t, _) -> t == tag) ss
                }

{- FOURMOLU_DISABLE -}
getCustomConf
    :: [(IP, Maybe HostName)]
    -> PortNumber
    -> QueryControls
    -> Options
    -> ResolveActions
    -> IO (LookupConf, [(IP, Maybe HostName, PortNumber)])
getCustomConf ips port ctl Options{..} ractions
  | null ips = return (conf, [])
  | otherwise = do
        let ahs = if optDisableV6NS then [ip4 | ip4@(IPv4{}, _) <- ips] else ips
            ahps = map (\(x,y) -> (x,y,port)) ahs
            aps = map (\(x,_) -> (x,port)) ahs
        return (conf{lconfSeeds = SeedsAddrPorts aps}, ahps)
  where
    conf =
        DNS.defaultLookupConf
            { lconfUDPRetry = 2
            , lconfQueryControls = ctl
            , lconfConcurrent = True
            , lconfActions = ractions
            }
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

mkHeader :: Reply -> String
mkHeader Reply{..} =
    ";; "
        ++ fromNameTag replyTag
        ++ ", Tx:"
        ++ show replyTxBytes
        ++ "bytes"
        ++ ", Rx:"
        ++ show replyRxBytes
        ++ "bytes"

----------------------------------------------------------------

saveResumption :: FilePath -> MVar () -> TQueue (NameTag, String) -> NameTag -> ByteString -> IO ()
saveResumption file lock tq name bs = do
    case extractInfo of
        Nothing -> return ()
        Just info -> atomically $ writeTQueue tq (name, info)
    safeAppendFile file lock (C8.pack (fromNameTag name) <> " " <> BS16.encode bs <> "\n")
  where
    extractInfo
        | "QUIC" == nameTagProto name || "H3" == nameTagProto name =
            case deserialiseOrFail $ BL.fromStrict bs of
                Left _ -> Nothing
                Right (info :: QUIC.ResumptionInfo) ->
                    Just $ next (QUIC.isResumptionPossible info) (QUIC.is0RTTPossible info)
        | otherwise =
            case deserialiseOrFail $ BL.fromStrict bs of
                Left _ -> Nothing
                Right (_ :: TLS.SessionID, sd :: TLS.SessionData) ->
                    Just $ next True (TLS.is0RTTPossible sd)
    next res rtt0 = "Next(Resumption:" ++ ok res ++ ", 0-RTT:" ++ ok rtt0 ++ ")"
    ok True = "OK"
    ok False = "NG"

loadResumption :: FilePath -> IO [(NameTag, ByteString)]
loadResumption file = map toKV . C8.lines <$> C8.readFile file
  where
    toKV l = (toNameTag $ C8.unpack k, fromRight "" $ BS16.decode $ C8.drop 1 v)
      where
        (k, v) = BS.break (== 32) l

safeAppendFile :: FilePath -> MVar () -> ByteString -> IO ()
safeAppendFile file lock bs = withMVar lock $ \_ -> BS.appendFile file bs
