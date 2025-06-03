module DNS.ByteCodec.Base16 where

-- GHC packages
import Data.Bits
import System.IO.Unsafe (unsafeDupablePerformIO)

-- other packages
import Data.Word8 (_0)

-- this package
import DNS.ByteCodec.Type (ByteArrayWrite (..), ByteIndex (..), ByteWriter (..))

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> :seti -XTypeApplications
-- >>> import Data.ByteString (ByteString)
-- >>> import Data.ByteString.Short (ShortByteString)
-- >>> type BS = ByteString
-- >>> type SBS = ShortByteString

{- FOURMOLU_DISABLE -}
-- | Hex encoding for byte-arrays like base16-bytestring
--
-- RFC 4648 test vectors - https://datatracker.ietf.org/doc/html/rfc4648#section-10
-- >>> encode @BS  @BS  ""
-- ""
-- >>> encode @BS  @BS  "f"
-- "66"
-- >>> encode @BS  @SBS "fo"
-- "666f"
-- >>> encode @SBS @BS  "foo"
-- "666f6f"
-- >>> encode @SBS @SBS "foob"
-- "666f6f62"
-- >>> encode @BS  @BS  "fooba"
-- "666f6f6261"
-- >>> encode @BS  @SBS "foobar"
-- "666f6f626172"
encode
    :: (ByteIndex s1, ByteWriter s2 a)
    => s1  -- ^ input bytes
    -> s2  -- ^ base16 output bytes
encode xs =
    unsafeDupablePerformIO $ unsafeCreateBytes dlen (encodeToBuf slen xs)
    {- We use `unsafeDupablePerformIO` in the same way as the original bytestring package.
       This means we must use algorithms that are safe under duplicate execution.
       For instance, algorithms that write different values to the same buffer position multiple times are dangerous. -}
  where
    slen = lengthByte xs
    dlen = slen * 2
{-# INLINEABLE encode #-}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
encodeToBuf
    :: (ByteIndex s1, ByteArrayWrite a)
    => Int -> s1 -> a -> IO ()
encodeToBuf slen src dst = go 0 0
  where
    toHex w
        | w < 10     = _0 + w
        | otherwise  = 87 + w  {- 97 (code of 'a') - 10 -} {- lower-case result like base64-bytestring package -}
    store i v = unsafeWriteByte dst i (toHex v)
    go ix ox
        | ix >= slen = pure ()
        | otherwise = do
              let w = unsafeIndexByte src ix
                  b1 = w `unsafeShiftR` 4 .&. 0x0F
                  b2 = w                  .&. 0x0F
              store  ox      b1
              store (ox + 1) b2
              go (ix + 1) (ox + 2)
{-# INLINEABLE encodeToBuf #-}
{- FOURMOLU_ENABLE -}
