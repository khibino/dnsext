{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MagicHash #-}

module DNS.ByteCodec.Type where

-- GHC exts
import Control.Monad.ST (RealWorld)
import Control.Monad
import Data.Char (ord)
import Data.IORef (IORef, modifyIORef, newIORef, readIORef, writeIORef)
import Foreign (Ptr, Storable (..))
import GHC.Exts (ByteArray#, MutableByteArray#, (+#), (-#))
import qualified GHC.Exts as GHC
import GHC.IO (IO (..))
import GHC.Int (Int (..))
import GHC.Word (Word8 (..))

-- bytestrings
import qualified Data.ByteString as BS
import Data.ByteString.Internal (ByteString)
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Short as SBS
import Data.ByteString.Short.Internal (ShortByteString (SBS))
import qualified Data.ByteString.Unsafe as BS

{- $setup
>>> :seti -XTypeApplications
>>> :seti -XOverloadedStrings
 -}

{- FOUMOLU_DISABLE -}
class ByteSeqRead b where
    unsafeRead1  :: b -> IO Word8
    restSize     :: b -> IO Int
    tryRead1     :: b -> IO () -> (Word8 -> IO ()) -> IO ()
    tryRead1 x zero byte = do
        len <- restSize x
        if len <= 0
            then zero
            else unsafeRead1 x >>= byte
{- minimal complete definition: unsafeRead1, restSize -}
{- FOUMOLU_ENABLE -}

class ByteSeqRead b => SeqReader s b | s -> b where
    unsafeBufferedRead :: s -> (b -> IO a) -> IO a

---

type BufferSBS = (ShortByteString, IORef Int, IORef Int)

{- FOUMOLU_DISABLE -}
instance ByteSeqRead BufferSBS where
    unsafeRead1 (SBS ba#, iref, rref) = do
        I# i# <- readIORef iref
        writeIORef iref $ I# (i# +# 1#)
        modifyIORef rref $ \(I# r#) -> I# (r# -# 1#)
        pure (W8# (GHC.indexWord8Array# ba# i#))
    restSize (_, _, rref) = readIORef rref
{- FOUMOLU_ENABLE -}

{- FOUMOLU_DISABLE -}
instance SeqReader ShortByteString BufferSBS where
    unsafeBufferedRead s k = do
        off   <- newIORef 0
        rest  <- newIORef (SBS.length s)
        k (s, off, rest)
{- FOUMOLU_ENABLE -}

type BufferBS = (ByteString, IORef Int, IORef Int)

{- FOUMOLU_DISABLE -}
instance ByteSeqRead BufferBS where
    unsafeRead1 (bs, iref, rref) = do
        i <- readIORef iref
        writeIORef iref (i + 1)
        modifyIORef rref $ \(I# r#) -> I# (r# -# 1#)
        pure (BS.unsafeIndex bs i)
    restSize (_, _, rref) = readIORef rref
{- FOUMOLU_ENABLE -}

{- FOUMOLU_DISABLE -}
instance SeqReader ByteString BufferBS where
    unsafeBufferedRead s k = do
        off   <- newIORef 0
        rest  <- newIORef (BS.length s)
        k (s, off, rest)
{- FOUMOLU_ENABLE -}

type BufferStr = (IORef String, IORef Int)

{- FOUMOLU_DISABLE -}
instance ByteSeqRead (IORef String, IORef Int) where
    unsafeRead1 (sref, rref)  = do
        x:xs <- readIORef sref
        writeIORef sref xs
        modifyIORef rref $ \(I# r#) -> I# (r# -# 1#)
        let code = ord x
        unless (0 <= code && code < 256) $
            fail $ "ByteSeqRead: String: out of byte: " ++ show code
        pure (fromIntegral code)
    restSize (_, rref) = readIORef rref
{- FOUMOLU_ENABLE -}

{- FOUMOLU_DISABLE -}
instance SeqReader String BufferStr where
    unsafeBufferedRead s k = do
        sref  <- newIORef s
        rest  <- newIORef (length s)
        k (sref, rest)
{- FOUMOLU_ENABLE -}

{- |
>>> readBytes @ShortByteString "foo"
[102,111,111]
>>> readBytes @ByteString "bar"
[98,97,114]
>>> readBytes @String "baz"
[98,97,122]
 -}
readBytes :: SeqReader s b => s -> IO [Word8]
readBytes s = unsafeBufferedRead s loop
  where
    loop b = do
        rlen <- restSize b
        let loop'
                | rlen > 0   = (:) <$> unsafeRead1 b <*> loop b
                | otherwise  = pure []
        loop'
