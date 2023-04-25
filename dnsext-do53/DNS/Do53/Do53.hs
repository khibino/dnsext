{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Do53 (
    udpTcpResolver
  , udpResolver
  , tcpResolver
  , vcResolver
  , checkRespM
  , toResult
  ) where

import Control.Exception as E
import qualified Data.ByteString as BS
import DNS.Types
import DNS.Types.Decode
import Network.Socket (HostName, close)
import qualified Network.UDP as UDP
import System.IO.Error (annotateIOError)

import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Query
import DNS.Do53.Types

-- | Check response for a matching identifier and question.  If we ever do
-- pipelined TCP, we'll need to handle out of order responses.  See:
-- https://tools.ietf.org/html/rfc7766#section-7
--
checkResp :: Question -> Identifier -> DNSMessage -> Bool
checkResp q seqno = isNothing . checkRespM q seqno

-- When the response 'RCODE' is 'FormatErr', the server did not understand our
-- query packet, and so is not expected to return a matching question.
--
checkRespM :: Question -> Identifier -> DNSMessage -> Maybe DNSError
checkRespM q seqno resp
  | identifier (header resp) /= seqno = Just SequenceNumberMismatch
  | FormatErr <- rcode $ flags $ header resp
  , []        <- question resp        = Nothing
  | [q] /= question resp              = Just QuestionMismatch
  | otherwise                         = Nothing

----------------------------------------------------------------

data TCPFallback = TCPFallback deriving (Show, Typeable)
instance Exception TCPFallback

-- | A resolver using UDP and TCP.
udpTcpResolver :: UDPRetry -> VCLimit -> Resolver
udpTcpResolver retry lim ri q qctl = udpResolver retry ri q qctl `E.catch` \TCPFallback -> tcpResolver lim ri q qctl

----------------------------------------------------------------

ioErrorToDNSError :: HostName -> String -> IOError -> IO Result
ioErrorToDNSError h protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = protoName ++ "@" ++ h
    aioe = annotateIOError ioe loc Nothing Nothing

----------------------------------------------------------------

-- | A resolver using UDP.
--   UDP attempts must use the same ID and accept delayed answers.
udpResolver :: UDPRetry -> Resolver
udpResolver retry ri@ResolvInfo{..} q _qctl =
    E.handle (ioErrorToDNSError rinfoHostName "UDP") $ go _qctl
  where
    -- Using only one socket and the same identifier.
    go qctl = bracket open UDP.close $ \sock -> do
        let send = UDP.send sock
            recv = UDP.recv sock
        ident <- ractionGenId rinfoActions
        loop retry ident qctl send recv

    loop 0 _ _ _ _ = E.throwIO RetryLimitExceeded
    loop cnt ident qctl0 send recv = do
        mrply <- solve ident qctl0 send recv
        case mrply of
          Nothing -> loop (cnt - 1) ident qctl0 send recv
          Just rply -> do
              let ans = replyDNSMessage rply
                  fl = flags $ header ans
                  tc = trunCation fl
                  rc = rcode fl
                  eh = ednsHeader ans
                  qctl = ednsEnabled FlagClear <> qctl0
              when tc $ E.throwIO TCPFallback
              if rc == FormatErr && eh == NoEDNS && qctl /= qctl0 then
                  loop cnt ident qctl send recv
                else
                  return $ toResult ri "UDP" rply

    solve ident qctl send recv = do
        let qry = encodeQuery ident q qctl
        ractionTimeout rinfoActions $ do
            _ <- send qry
            let tx = BS.length qry
            getAnswer ident recv tx

    getAnswer ident recv tx = do
        ans <- recv `E.catch` \e -> E.throwIO $ NetworkFailure e
        now <- ractionGetTime rinfoActions
        let showHex8 w
              | w >= 16    = showHex w
              | otherwise  =  ('0' :) . showHex w
            dumpBS = ("\"" ++) . (++ "\"" ) . foldr (\w s -> "\\x" ++ showHex8 w s) "" . BS.unpack
        case decodeAt now ans of
            Left  e -> putStrLn ("udpResolver.getAnswer: decodeAt Left: " ++ rinfoHostName ++ ", " ++ dumpBS ans) *> E.throwIO e
            Right msg
              | checkResp q ident msg -> do
                    let rx = BS.length ans
                    return $ Reply msg tx rx
              -- Just ignoring a wrong answer.
              | otherwise             -> putStrLn ("udpResolver.getAnswer: checkResp-error: " ++ rinfoHostName ++ ", " ++ show msg) *>  getAnswer ident recv tx

    open = UDP.clientSocket rinfoHostName (show rinfoPortNumber) True -- connected

----------------------------------------------------------------

-- | A resolver using TCP.
tcpResolver :: VCLimit -> Resolver
tcpResolver lim ri@ResolvInfo{..} q qctl = vcResolver "TCP" perform ri q qctl
  where
    -- Using a fresh connection
    perform solve = bracket open close $ \sock -> do
        let send = sendVC $ sendTCP sock
            recv = recvVC lim $ recvTCP sock
        solve send recv

    open = openTCP rinfoHostName rinfoPortNumber

-- | Generic resolver for virtual circuit.
vcResolver :: String -> ((Send -> RecvMany -> IO Reply) -> IO Reply) -> Resolver
vcResolver proto perform ri@ResolvInfo{..} q _qctl =
    E.handle (ioErrorToDNSError rinfoHostName proto) $ go _qctl
  where
    go qctl0 = do
        rply <- perform $ solve qctl0
        let ans = replyDNSMessage rply
            fl = flags $ header ans
            rc = rcode fl
            eh = ednsHeader ans
            qctl = ednsEnabled FlagClear <> qctl0
        -- If we first tried with EDNS, retry without on FormatErr.
        if rc == FormatErr && eh == NoEDNS && qctl /= qctl0 then do
            toResult ri proto <$> perform (solve qctl)
          else
            return $ toResult ri proto rply

    solve qctl send recv = do
        -- Using a fresh identifier.
        ident <- ractionGenId rinfoActions
        let qry = encodeQuery ident q qctl
        mres <- ractionTimeout rinfoActions $ do
            _ <- send qry
            let tx = BS.length qry
            getAnswer ident recv tx
        case mres of
           Nothing  -> E.throwIO TimeoutExpired
           Just res -> return res

    getAnswer ident recv tx = do
        (rx,bss) <- recv `E.catch` \e -> E.throwIO $ NetworkFailure e
        now <- ractionGetTime rinfoActions
        case decodeChunks now bss of
            Left  e   -> E.throwIO e
            Right (msg,_) -> case checkRespM q ident msg of
                Nothing  -> return $ Reply msg tx rx
                Just err -> E.throwIO err

toResult :: ResolvInfo -> String -> Reply -> Result
toResult ResolvInfo{..} tag rply = Result {
    resultHostName   = rinfoHostName
  , resultPortNumber = rinfoPortNumber
  , resultTag        = tag
  , resultReply      = rply
  }
