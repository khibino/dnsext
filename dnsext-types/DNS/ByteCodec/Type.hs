{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE UnboxedTuples #-}

module DNS.ByteCodec.Type where

-- GHC exts
import Control.Monad.ST (RealWorld)
import Foreign (Ptr, Storable (..))
import GHC.Exts (ByteArray#, MutableByteArray#)
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

class ByteIndex s where
    unsafeIndexByte :: s -> Int -> Word8
    lengthByte :: s -> Int

---

-- |
-- interface to write like byte-array
--
-- Why not use Storable directly:
--   `pokeByteOff` require `Ptr a`, but `Ptr a` assumes pinned memory.
--   However, on the other hand, `MutableByteArray#` can be used with NOT pinned memory.
--   When initializing `ShortByteString`, this not pinned `MutableByteArray#` is also used.
class ByteArrayWrite a where
    unsafeWriteByte :: a -> Int -> Word8 -> IO ()

class ByteArrayWrite a => ByteWriter s a | s -> a where
    unsafeCreateBytes :: Int -> (a -> IO ()) -> IO s

---

data BA = BA# ByteArray#
data MBA = MBA# (MutableByteArray# RealWorld)

---

instance ByteIndex ShortByteString where
    unsafeIndexByte (SBS ba#) (I# i#) = W8# (GHC.indexWord8Array# ba# i#)
    {-# INLINEABLE unsafeIndexByte #-}
    lengthByte = SBS.length
    {-# INLINEABLE lengthByte #-}

instance ByteIndex ByteString where
    unsafeIndexByte = BS.unsafeIndex
    {-# INLINEABLE unsafeIndexByte #-}
    lengthByte = BS.length
    {-# INLINEABLE lengthByte #-}

---

instance ByteArrayWrite MBA where
    unsafeWriteByte (MBA# mba#) (I# i#) (W8# w#) =
        IO $ \s -> case GHC.writeWord8Array# mba# i# w# s of s1 -> (# s1, () #)
    {-# INLINEABLE unsafeWriteByte #-}

instance ByteArrayWrite (Ptr Word8) where
    unsafeWriteByte = pokeByteOff
    {-# INLINEABLE unsafeWriteByte #-}

---

instance ByteWriter ShortByteString MBA where
    unsafeCreateBytes len h = do
        mba <- new len
        h mba
        freeze mba
      where
        new (I# len#) = IO $ \s -> case GHC.newByteArray# len# s of (# s1, mba# #) -> (# s1, MBA# mba# #)
        freeze (MBA# mba#) = IO $ \s -> case GHC.unsafeFreezeByteArray# mba# s of (# s1, ba# #) -> (# s1, SBS ba# #)

instance ByteWriter ByteString (Ptr Word8) where
    unsafeCreateBytes = BS.create
