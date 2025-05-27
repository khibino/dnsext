module DNS.ByteCodec.Base32Hex where

-- GHC packages
import Control.Monad
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
-- | Encode byte-arrays using the
-- <https://tools.ietf.org/html/rfc4648#section-7 RFC4648 base32hex>
-- encoding with no padding as specified for the
-- <https://tools.ietf.org/html/rfc5155#section-3.3 RFC5155 Next Hashed Owner Name>
-- field.
--
-- RFC 4648 test vectors - https://datatracker.ietf.org/doc/html/rfc4648#section-10
-- >>> encode @BS  @BS  ""
-- ""
-- >>> encode @BS  @BS  "f"
-- "CO"
-- >>> encode @BS  @BS  "fo"
-- "CPNG"
-- >>> encode @BS  @BS  "foo"
-- "CPNMU"
-- >>> encode @BS  @SBS "foob"
-- "CPNMUOG"
-- >>> encode @SBS @BS  "fooba"
-- "CPNMUOJ1"
-- >>> encode @SBS @SBS "foobar"
-- "CPNMUOJ1E8"
--
-- test vectors from base-encoding package
-- >>> encode @BS @BS   "\x00\x00"
-- "0000"
-- >>> encode @BS @SBS  "4:20"
-- "6GT34C0"
-- >>> encode @SBS @BS  "\xFF\239"
-- "VVNG"
--
-- test vectors from base32 package
-- >>> encode @SBS @SBS "Sun"
-- "ADQMS"
encode
    :: (ByteIndex s1, ByteWriter s2 a)
    => s1  -- ^ input bytes
    -> s2  -- ^ base32hex output bytes
encode xs =
    unsafeDupablePerformIO $ unsafeCreateBytes dlen (encodeToBuf slen xs)
    {- We use `unsafeDupablePerformIO` in the same way as the original bytestring package.
       This means we must use algorithms that are safe under duplicate execution.
       For instance, algorithms that write different values to the same buffer position multiple times are dangerous. -}
  where
    slen = lengthByte xs
    dlen = (8 * slen + 4) `div` 5
{-# INLINEABLE encode #-}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
encodeToBuf
    :: (ByteIndex s1, ByteArrayWrite a)
    => Int -> s1 -> a -> IO ()
encodeToBuf slen src dst = go 0 0 0 0
  where
    toHex32 w
        | w < 10     = _0 + w
        | otherwise  = 55 + w  {- 65 (code of 'A') - 10 -} {- upper-case result adjust to RFC 4648 examples -}
    store i v = unsafeWriteByte dst i (toHex32 v)
    go ix ox br r
        | ix >= slen = when (r > 0) $ store ox br
        | otherwise = do
            let w = unsafeIndexByte src ix
                b1 =   br .|. w `unsafeShiftR` (3 + r)     -- 1st bits of case1
                b2 =         (w `shift` (2 - r)) .&. 0x1F  -- 2nd bits of case2 or spilled bits of case1
                rn = (r + 8) `rem` 5
                store1 = store  ox      b1
                store2 = store (ox + 1) b2
                case1 = do -- case for 8bit - 9bit
                    go (ix + 1) (ox + 1) b2 rn
                case2 = do -- case for 10bit - 14bit
                    let b3 = (w `shift` (7 - r)) .&. 0x1F  --                      spilled bits of case2
                    go (ix + 1) (ox + 2) b3 rn

            store1
            if r < 2 then case1 else store2 >> case2
{-# INLINEABLE encodeToBuf #-}
{- FOURMOLU_ENABLE -}
