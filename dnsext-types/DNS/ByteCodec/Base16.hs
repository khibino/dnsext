module DNS.ByteCodec.Base16 where

-- GHC packages
import Control.Monad
import Data.Bits
import System.IO.Error (tryIOError)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- other packages
import Data.Word8 (_0, _9, _A, _F, _a, _f)

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

{- FOURMOLU_DISABLE -}
-- | Decode hex byte-array
--
-- >>> decode @BS  @BS  ""
-- Right ""
-- >>> decode @BS  @BS  "66"
-- Right "f"
-- >>> decode @BS  @SBS "666f"
-- Right "fo"
-- >>> decode @SBS @BS  "666f6f"
-- Right "foo"
-- >>> decode @SBS @SBS "666f6f62"
-- Right "foob"
-- >>> decode @BS  @BS  "666f6f6261"
-- Right "fooba"
-- >>> decode @BS  @SBS "666f6f626172"
-- Right "foobar"
-- >>> decode @BS  @BS  "a"
-- Left ...
-- >>> decode @BS  @BS  "xx"
-- Left ...
decode
    :: (Show s1, ByteIndex s1, ByteWriter s2 a)
    => s1
    -> Either String s2
decode xs =
    unsafeDupablePerformIO $ either (Left . show) Right <$> tryIOError (unsafeCreateBytes dlen $ decodeToBuf slen xs)
  where
    slen = lengthByte xs
    dlen = slen `quot` 2
{-# INLINEABLE decode #-}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
decodeToBuf
    :: (Show s1, ByteIndex s1, ByteArrayWrite a)
    => Int -> s1 -> a -> IO ()
decodeToBuf slen src dst = do
    let r = slen `rem` 2
        left = fail . ("Base16.decode: " ++)
    unless (r == 0) $
        left ("input has invalid length: " ++ show slen ++ " / " ++ show src)
    loop left
  where
    fromHex w left right
        | _A <= w && w <= _F  = right $ w - 55  {- 65 (code of 'A') - 10 -}
        | _a <= w && w <= _f  = right $ w - 87  {- 97 (code of 'a') - 10 -}
        | _0 <= w && w <= _9  = right $ w - _0
        | otherwise           = left ("not base16 format: " ++ show src)

    store8 i v = unsafeWriteByte dst i v
    stores n f1 f2 = store8 n (f1 `unsafeShiftL` 4 .|. f2)

    loop left = go 0 0
      where
        fromH w = fromHex w left
        go ix ox
            | r >= 2     = fromH b1 $ \f1 -> fromH b2 $ \f2 -> do { stores ox f1 f2 ; go (ix + 2) (ox + 1) }
            | r == 0     = pure ()
            | otherwise  = left $ "internal error. input has invalid length: " ++ show slen ++ " / " ++ show src
          where
            r = slen - ix
            ~b1 = src `unsafeIndexByte`  ix
            ~b2 = src `unsafeIndexByte` (ix + 1)
{-# INLINEABLE decodeToBuf #-}
{- FOURMOLU_ENABLE -}
