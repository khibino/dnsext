{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Resolver53 where

-- GHC packages
import Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.List.NonEmpty as NE
import System.Timeout (timeout)

-- other packages
import Network.Socket
import qualified Network.Socket.ByteString as NSB

-- dnsext packages
import DNS.Do53.Client (QueryControls, FlagOp (FlagClear), ednsEnabled)
import DNS.Do53.Internal
import qualified DNS.Log as Log
import DNS.Types
import DNS.Types.Decode

-- this package
import DNS.Iterative.Imports


-- | Check response for a matching identifier and question.  If we ever do
-- pipelined TCP, we'll need to handle out of order responses.  See:
-- https://tools.ietf.org/html/rfc7766#section-7
checkResp :: Question -> Identifier -> DNSMessage -> Bool
checkResp q seqno = isNothing . checkRespM q seqno

caseNoEDNS :: Reply -> QueryControls -> Maybe QueryControls
caseNoEDNS rply qctl0
    | rc == FormatErr && eh == NoEDNS && qctl /= qctl0 = Just qctl
    | otherwise = Nothing
  where
    ans = replyDNSMessage rply
    rc = rcode ans
    eh = ednsHeader ans
    qctl = ednsEnabled FlagClear <> qctl0

timeoutDNS' :: String -> Int -> IO a -> IO a
timeoutDNS' tag micro action = maybe (throwIO $ DNSErrorInfo TimeoutExpired tag) pure =<< timeout micro action

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | A resolver using UDP and TCP.
--   fallback once for NoEDNS case
udpTcpResolver1 :: OneshotResolver
udpTcpResolver1 ri@ResolveInfo{rinfoActions = ResolveActions{..}} q qctl0 = timeout' $ do
    er1 <- udpResolver1 ri q qctl0
    case er1 of
        e1@(Left {})                  -> return e1
        __@(Right rply1)  -> case caseNoEDNS rply1 qctl0 of
            Nothing                   -> handleTC rply1 qctl0
            Just qctl1            -> do
                er2 <- udpResolver1 ri q qctl1
                case er2 of
                    e2@(Left {})      -> return e2
                    __@(Right rply2)  -> handleTC rply2 qctl1
  where
    ~qtag = queryTag q (nameTag ri "UDP-TCP") qctl0
    timeout' = timeoutDNS' ("iter.udpTcpResolver1: " ++ qtag) ractionTimeoutTime
    handleTC rply qctl
        | tc         = tcpResolver1 ri q qctl
        | otherwise  = return $ Right rply
      where
        tc = trunCation $ flags $ replyDNSMessage rply

{- FOURMOLU_ENABLE -}

-- | one-shot UDP resolver
--   - ignoring rinfoUDPRetry
--   - no fallback for NoEDNS case
udpResolver1 :: OneshotResolver
udpResolver1 ri@ResolveInfo{rinfoActions = ResolveActions{..}, ..} q qctl0 = do
    logNoShort qtag
    tryDNS' logNoShort qtag (go qctl0)
  where
    logNoShort s = unless ractionShortLog (ractionLog Log.DEMO Nothing [s])
    tag = nameTag ri "UDP"
    ~qtag = queryTag q tag qctl0

    -- Using only one socket and the same identifier.
    go qctl = bracket open close $ \sock -> do
        ractionSetSockOpt sock
        let send bs = NSB.send sock bs
            recv = NSB.recv sock 2048
        ident <- ractionGenId
        sendQueryRecvAnswer ident qctl send recv

    sendQueryRecvAnswer ident qctl send recv = do
        let qry = encodeQuery ident q qctl
        _ <- send qry
        let tx = BS.length qry
        recvAnswer ident recv tx

    recvAnswer ident recv tx = do
        ans <- recv
        now <- ractionGetTime
        case decodeAt now ans of
            Left e -> do
                ractionLog Log.DEBUG Nothing $
                    let showHex8 w
                            | w >= 16 = showHex w
                            | otherwise = ('0' :) . showHex w
                        dumpBS = ("\"" ++) . (++ "\"") . foldr (\w s -> "\\x" ++ showHex8 w s) "" . BS.unpack
                     in ["udpResolver1.recvAnswer: decodeAt Left: ", show rinfoIP ++ ", ", dumpBS ans]
                E.throwIO e
            Right msg
                | checkResp q ident msg -> do
                    let rx = BS.length ans
                    return $
                        Reply
                            { replyTag = tag
                            , replyDNSMessage = msg
                            , replyTxBytes = tx
                            , replyRxBytes = rx
                            }
                -- Just ignoring a wrong answer.
                | otherwise -> do
                    ractionLog
                        Log.DEBUG
                        Nothing
                        ["udpResolver1.recvAnswer: checkResp error: ", show rinfoIP, ", ", show msg]
                    recvAnswer ident recv tx

    open = do
        let host = show rinfoIP
            port = show rinfoPort
            hints = defaultHints{addrSocketType = Datagram, addrFlags = [AI_ADDRCONFIG]}
        addr <- NE.head <$> getAddrInfo (Just hints) (Just host) (Just port)
        E.bracketOnError (openSocket addr) close $ \s -> do
            let sa = addrAddress addr
            connect s sa
            return s

-- | A resolver using TCP.
tcpResolver1 :: OneshotResolver
tcpResolver1 ri@ResolveInfo{rinfoActions = ResolveActions{..}, ..} q qctl =
    -- Using a fresh connection
    bracket open close $ \sock -> do
        ractionSetSockOpt sock
        let send bs = sendVC (sendTCP sock) bs
            recv = recvVC rinfoVCLimit $ recvTCP sock
        vcResolver1 tag send recv ri q qctl
  where
    tag = nameTag ri "TCP"
    open = openTCP rinfoIP rinfoPort

-- | Generic resolver for virtual circuit.
vcResolver1 :: NameTag -> (BS -> IO ()) -> IO BS -> OneshotResolver
vcResolver1 tag send recv ResolveInfo{rinfoActions = ResolveActions{..}} q qctl0 = do
    logNoShort qtag
    tryDNS' logNoShort qtag (go qctl0)
  where
    logNoShort s = unless ractionShortLog (ractionLog Log.DEMO Nothing [s])
    ~qtag = queryTag q tag qctl0
    go qctl = sendQueryRecvAnswer qctl

    sendQueryRecvAnswer qctl = do
        -- Using a fresh identifier.
        ident <- ractionGenId
        let qry = encodeQuery ident q qctl
        _ <- send qry
        let tx = BS.length qry
        res <- recvAnswer ident tx
        return res

    recvAnswer ident tx = do
        bs <- recv
        now <- ractionGetTime
        case decodeAt now bs of
            Left e -> E.throwIO e
            Right msg -> case checkRespM q ident msg of
                Nothing ->
                    return $
                        Reply
                            { replyTag = tag
                            , replyDNSMessage = msg
                            , replyTxBytes = tx
                            , replyRxBytes = BS.length bs
                            }
                Just err -> E.throwIO err
