{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.CtlRecv (
    -- * Controlled receiving
    Check,
    CtlRecv,
    ctlRecvBreak,
    newCtlRecv,
    Terminate (..),
    withControlledRecv,
    getLeftover,

    -- * Internal
    controlledRecv,
    Result (..),
) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef

-- | Return 'True' when a break (aka Timeout) happens.
type Check = IO Bool

-- | Control data for a receiving function.
data CtlRecv = CtlRecv
    { ctlRecvBreak :: Check
    , ctlRecvBuillder :: IORef (Int, [ByteString] -> [ByteString])
    }

-- | Creating 'CtlRecv'.
newCtlRecv
    :: Check
    -> IO CtlRecv
newCtlRecv ctlRecvBreak = do
    ctlRecvBuillder <- newIORef (0, id)
    return CtlRecv{..}

-- | The reason why the receiving function is terminated.
data Terminate
    = -- | End of file.
      EOF
    | -- | When 'Check' returns 'False', 'Break' is retuned. 'Break'
      --   is timeout in the normal case.
      Break
    deriving (Eq, Show)

-- | Result.
data Result
    = Terminate Terminate
    | NotEnough
    | NBytes ByteString
    deriving (Eq, Show)

-- | Controlled receiving function.
--
--   one-shot blocking on `ctlRecvBreak`
controlledRecv :: CtlRecv -> (Int -> IO ByteString) -> Int -> IO Result
controlledRecv CtlRecv{..} recvN len = do
    brk <- ctlRecvBreak
    (blen, builder) <- readIORef ctlRecvBuillder
    if brk
        then
            return $ Terminate Break
        else do
            let wantN = len - blen
            bs <- recvN wantN
            let n = BS.length bs
            if n == 0
                then return $ Terminate EOF
                else do
                    let builder' = builder . (bs :)
                    if n == wantN
                        then do
                            let finalBS = BS.concat $ builder' []
                            writeIORef ctlRecvBuillder (0, id)
                            return $ NBytes finalBS
                        else do
                            let blen' = blen + n
                            writeIORef ctlRecvBuillder (blen', builder')
                            return NotEnough

-- | Use to get leftover for 'Terminate'.
getLeftover :: CtlRecv -> IO ByteString
getLeftover CtlRecv{..} = do
    (_blen, builder) <- readIORef ctlRecvBuillder
    let leftover = BS.concat $ builder []
    return leftover

-- | Calling an action with 'ByteString' of the exact size.
--
--   event loop, blocking on waiting events.
withControlledRecv
    :: CtlRecv
    -> (Int -> IO ByteString)
    -- ^ Receiving function
    -> Int
    -- ^ How many bytes are wanted.
    -> (ByteString -> IO a)
    -- ^ An action which receives 'ByteString' of the exact size.
    -> IO (Either Terminate a)
withControlledRecv ctl recvN len action = go
  where
    go = do
        r <- controlledRecv ctl recvN len
        case r of
            NotEnough -> go
            Terminate t -> return $ Left t
            NBytes bs -> Right <$> action bs
