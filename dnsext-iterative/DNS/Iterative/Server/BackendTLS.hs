{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.BackendTLS where

import Control.Concurrent.STM
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Sequence (Seq, ViewL (..), (<|), (|>))
import qualified Data.Sequence as Seq

recvToBuffers :: IO ByteString -> Buffers -> IO ()
recvToBuffers recv Buffers{..} = do
    c <- recv
    atomically $ putFIFO recvBuffer c

sendFromBuffers :: (Chunk -> IO a) -> Buffers -> IO a
sendFromBuffers send Buffers{..} = do
    c <- atomically $ getFIFO sendBuffer retry pure
    send c

---

type Chunk = ByteString
type Chunks = Seq Chunk

newFIFO :: IO (TVar Chunks)
newFIFO = newTVarIO Seq.empty

{- FOURMOLU_DISABLE -}
getFIFO :: TVar Chunks -> STM a -> (Chunk -> STM a) -> STM a
getFIFO ref nothing just = do
    q0 <- readTVar ref
    case Seq.viewl q0 of
      EmptyL   -> nothing
      a :< q1  -> writeTVar ref q1 >> just a
{- FOURMOLU_ENABLE -}

putFIFO :: TVar Chunks -> Chunk -> STM ()
putFIFO ref c = modifyTVar' ref (|> c)

ungetFIFO :: Chunk -> TVar Chunks -> STM ()
ungetFIFO c ref = modifyTVar' ref (c <|)

{- FOURMOLU_DISABLE -}
nbyteFromFIFO :: TVar Chunks -> Int -> STM ByteString
nbyteFromFIFO ref =
    go id
  where
    go a n = do
        c <- getFIFO ref retry pure
        let clen = BS.length c
        case compare clen n of
            LT -> go (a . (c :)) (n - clen)
            EQ ->                     pure (BS.concat $ a [c])
            GT -> ungetFIFO tl ref >> pure (BS.concat $ a [hd])
              where (hd, tl) = BS.splitAt clen c
{- FOURMOLU_ENABLE -}

data Buffers =
    Buffers
    { recvBuffer :: TVar Chunks
    , sendBuffer :: TVar Chunks
    }

getBuffers :: IO Buffers
getBuffers = Buffers <$> newFIFO <*> newFIFO

withRestoreRecvBuf :: Buffers -> STM (Either e a) -> STM (Either e a)
withRestoreRecvBuf Buffers{..} estm = do
    cs0 <- readTVar recvBuffer
    e <- estm
    either (\err -> writeTVar recvBuffer cs0 >> pure (Left err)) (pure . Right) e
