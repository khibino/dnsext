{-# LANGUAGE OverloadedStrings #-}

module DNS.Do53.IO (
    -- * Receiving DNS messages
    recvTCP
  , recvVC
  , decodeVCLength
    -- * Sending pre-encoded messages
  , sendUDP
  , sendTCP
  , sendVC
  , encodeVCLength
  ) where

import qualified Control.Exception as E
import DNS.Types hiding (Seconds)
import DNS.Types.Decode
import qualified Data.ByteString as BS
import Network.Socket (Socket)
import Network.Socket.ByteString (recv)
import qualified Network.Socket.ByteString as Socket
import System.IO.Error

import DNS.Do53.Imports

----------------------------------------------------------------

recvVC :: (Int -> IO ByteString) -> IO DNSMessage
recvVC rcv = do
    len <- decodeVCLength <$> rcv 2
    bs <- rcv len
    now <- getEpochTime
    case decodeAt now bs of
        Left e    -> E.throwIO e
        Right msg -> return msg

decodeVCLength :: ByteString -> Int
decodeVCLength bs = case BS.unpack bs of
  [hi, lo] -> 256 * fromIntegral hi + fromIntegral lo
  _        -> 0              -- never reached

recvTCP :: Socket -> Int -> IO ByteString
recvTCP sock len = recv1 `E.catch` \e -> E.throwIO $ NetworkFailure e
  where
    recv1 = do
        bs1 <- recvCore len
        if BS.length bs1 == len then
            return bs1
          else do
            loop bs1
    loop bs0 = do
        let left = len - BS.length bs0
        bs1 <- recvCore left
        let bs = bs0 <> bs1
        if BS.length bs == len then
            return bs
          else
            loop bs
    eofE = mkIOError eofErrorType "connection terminated" Nothing Nothing
    recvCore len0 = do
        bs <- recv sock len0
        if bs == "" then
            E.throwIO eofE
          else
            return bs

----------------------------------------------------------------

-- | Send an encoded 'DNSMessage' datagram over UDP.  The message length is
-- implicit in the size of the UDP datagram.  With TCP you must use 'sendVC',
-- because TCP does not have message boundaries, and each message needs to be
-- prepended with an explicit length.  The socket must be explicitly connected
-- to the destination nameserver.
--
sendUDP :: Socket -> ByteString -> IO ()
sendUDP sock bs = void $ Socket.send sock bs

-- | Send a single encoded 'DNSMessage' over VC.  An explicit length is
-- prepended to the encoded buffer before transmission.  If you want to
-- send a batch of multiple encoded messages back-to-back over a single
-- VC connection, and then loop to collect the results, use 'encodeVC'
-- to prefix each message with a length, and then use 'sendAll' to send
-- a concatenated batch of the resulting encapsulated messages.
--
sendVC :: ([ByteString] -> IO ()) -> ByteString -> IO ()
sendVC writev bs = do
    let lb = encodeVCLength $ BS.length bs
    writev [lb,bs]

sendTCP :: Socket -> [ByteString] -> IO ()
sendTCP = Socket.sendMany

-- | Encapsulate an encoded 'DNSMessage' buffer for transmission over a VC
-- virtual circuit.  With VC the buffer needs to start with an explicit
-- length (the length is implicit with UDP).
--
encodeVCLength :: Int -> ByteString
encodeVCLength len = BS.pack [fromIntegral u, fromIntegral l]
    where
      (u,l) = len `divMod` 256
