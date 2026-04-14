{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.ProxyVC where

import Control.Exception (SomeException, toException)
import Control.Concurrent.STM
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Functor
import Data.IORef
import Data.String
import Numeric.Natural (Natural)

import DNS.Types (DNSError (DecodeError))
import DNS.Types.Decode (decodeVCLength)
import DNS.Types.Encode (encodeVCLength)

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> import Data.List
-- >>> import Data.IORef

type BS = ByteString

brecvN :: IORef BS -> IO BS -> Int -> IO BS
brecvN buf recvBS n = do
    bbs <- readIORef buf
    let caseRecv = do
            rbs <- recvBS
            let (hd, tl) = BS.splitAt n rbs
            writeIORef buf tl
            return hd
        caseBuf = do
            let (hd, tl) = BS.splitAt n bbs
            writeIORef buf tl
            return hd
        dispatch
            | bbs == mempty  = caseRecv
            | otherwise      = caseBuf
    dispatch

-- |
-- >>> mockRecv store = do { bss <- readIORef store; maybe (return mempty) (\(x,xs) -> writeIORef store xs >> pure x) $ uncons bss }
-- >>> getMockRecv bss = do { store <- newIORef bss; return (mockRecv store) }
-- >>> getMockRecvN bss = do { recv <- getMockRecv bss; mkRecvN recv }
-- >>> recvN <- getMockRecvN ["abcde"]
-- >>> recvN 3
-- "abc"
-- >>> recvN 3
-- "de"
-- >>> recvN 3
-- ""
-- >>> recvN <- getMockRecvN ["ab", "cde"]
-- >>> recvN 5
-- "ab"
-- >>> recvN 5
-- "cde"
-- >>> recvN 5
-- ""
mkRecvN :: IO BS -> IO (Int -> IO BS)
mkRecvN recvBS = do
    buf <- newIORef mempty
    return $ brecvN buf recvBS

--------------------------------------------------------------------------------

data PxInput
    = InputEOF
    | InputError SomeException
    | InputBytes BS
    deriving Show

{- FOURMOLU_DISABLE -}
inputFilledN
    :: (Int -> IO BS)
    -> Int
    -> IO PxInput
inputFilledN recvN n = loop id n
  where
    loop as r1 = do
        bs <- recvN r1 :: IO BS
        let len = BS.length bs
            r2 = r1 - len
            inputErr = InputError . toException . DecodeError . ("ProxyVC.inputFilledN: " ++)
            eofCase
                | null (as [])  = InputEOF
                | otherwise     = inputErr $ "short input: " ++ show (BS.take 16 (BS.concat $ as []) <> fromString " ...")
            dispatch
                | r2 < 0     = return $ inputErr "recvN is inconsistent"
                | len == 0   = return   eofCase
                | r2 > 0     = loop (as . (bs :)) r2
                | otherwise  = return $ InputBytes $ BS.concat $ as []
        dispatch
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
preceiver
    :: (Int -> IO PxInput)
    -> TBQueue PxInput
    -> IO ()
preceiver filledN inputQ = loop
  where

    loop = recvLen (recvVC loop)

    recvLen recvVC_ = do
        inp <- filledN 2
        case inp of
            InputEOF       -> enqueue inp
            InputError{}   -> enqueue inp
            InputBytes bs  -> recvVC_ (decodeVCLength bs)

    recvVC next len = do
        inp <- filledN len
        let errEOF = InputError $ toException $ DecodeError "ProxyVC.preceiver: inconsistent EOF position"
        case inp of
            InputEOF       -> enqueue  errEOF  -- EOF found on strange position
            InputError{}   -> enqueue  inp
            InputBytes bs  -> enqueue (InputBytes bs) >> next

    enqueue ev = atomically $ writeTBQueue inputQ ev
{- FOURMOLU_DISABLE -}

--------------------------------------------------------------------------------

type PxOutput = BS

psender
    :: ([BS] -> IO ())
    -> TBQueue PxOutput
    -> IO ()
psender sendMany outputQ = loop
  where
    loop = do
        bs <- atomically (readTBQueue outputQ)
        sendMany [encodeVCLength (BS.length bs), bs]
        loop

--------------------------------------------------------------------------------

data StTerm
    = TmEOF
    | TmError SomeException
    deriving Show

{- FOURMOLU_DISABLE -}
-- |
-- Proxy Session
--   - isolate from asyncronous cancellations
--   - handling blocking I/O calls
data PxSession
    = PxSession
      { inputQ   :: TBQueue PxInput
      , outputQ  :: TBQueue PxOutput
      , termTM   :: TMVar StTerm  -- after read terminated state from real receiver
      , quitTM   :: TMVar ()
      }
{- FOURMOLU_ENABLE -}

type PxSessions = TBQueue PxSession

newPxSessions :: Int -> IO (TBQueue PxSession)
newPxSessions sz = newTBQueueIO $ sessionsBound sz

sessionsBound :: Int -> Natural
sessionsBound n
    | n <= 0     = 16
    | otherwise  = fromIntegral n

--------------------------------------------------------------------------------

startPxSession :: Int -> TBQueue PxSession -> IO PxSession
startPxSession sz sessQ = atomically $ newPxSession sz >>= \sess -> writeTBQueue sessQ sess $> sess

{- FOURMOLU_DISABLE -}
newPxSession :: Int -> STM PxSession
newPxSession sz = do
    inputQ   <- newInputs sz
    termTM   <- newEmptyTMVar
    outputQ  <- newOutputs sz
    quitTM   <- newEmptyTMVar
    return PxSession{..}
{- FOURMOLU_ENABLE -}

newInputs :: Int -> STM (TBQueue PxInput)
newInputs sz = newTBQueue $ pendindBound sz

newOutputs :: Int -> STM (TBQueue PxOutput)
newOutputs sz = newTBQueue $ pendindBound sz

pendindBound :: Int -> Natural
pendindBound n
    | n <= 0     = 16
    | otherwise  = fromIntegral n

waitClose :: PxSession -> IO ()
waitClose PxSession{..} = atomically $ readTMVar quitTM  -- rereadable closed state

--------------------------------------------------------------------------------

acceptPxSession :: TBQueue PxSession -> IO PxSession
acceptPxSession sessQ = atomically $ readTBQueue sessQ

{- FOURMOLU_DISABLE -}
casesInput
    :: PxSession
    -> STM a
    -> (SomeException -> STM a)
    -> (BS -> STM a)
    -> STM a
casesInput PxSession{..} hEof hErr hBytes = do
    inp <- readTBQueue inputQ
    case inp of
        InputEOF       -> putTMVar termTM  TmEOF        >> hEof
        InputError se  -> putTMVar termTM (TmError se)  >> hErr se
        InputBytes bs  -> hBytes bs
{- FOURMOLU_ENABLE -}

termState :: PxSession -> STM StTerm
termState PxSession{..} = readTMVar termTM  -- re-readable terminated input state

closePxSession :: PxSession -> IO ()
closePxSession PxSession{..} = atomically $ putTMVar quitTM ()
