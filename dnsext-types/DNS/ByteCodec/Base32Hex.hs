module DNS.ByteCodec.Base32Hex where

-- GHC packages
import Control.Monad
import Data.Bits
import System.IO.Error (tryIOError, ioeGetErrorType, ioeGetErrorString)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- other packages
import Data.Word8 (_0, _9, _A, _V, _a, _v)

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

{- FOURMOLU_DISABLE -}
-- | Decode base32hex byte-array
--
-- RFC 4648 test vectors - https://datatracker.ietf.org/doc/html/rfc4648#section-10
-- >>> decode @BS  @BS  ""
-- Right ""
-- >>> decode @BS  @BS  "CO"
-- Right "f"
-- >>> decode @BS  @SBS "CPNG"
-- Right "fo"
-- >>> decode @SBS @BS  "CPNMU"
-- Right "foo"
-- >>> decode @SBS @SBS "CPNMUOG"
-- Right "foob"
-- >>> decode @BS  @BS  "CPNMUOJ1"
-- Right "fooba"
-- >>> decode @BS  @SBS "CPNMUOJ1E8"
-- Right "foobar"
--
-- error tests
-- >>> decode @SBS @BS  "C"
-- Left ... invalid length: ...
-- >>> decode @SBS @SBS "xx"
-- Left ... not base32hex ...
decode
    :: (Show s1, ByteIndex s1, ByteWriter s2 a)
    => s1
    -> Either String s2
decode xs =
    unsafeDupablePerformIO $ either left Right <$> tryIOError (unsafeCreateBytes dlen $ decodeToBuf slen xs)
  where
    left e = Left $ show (ioeGetErrorType e) ++ ": " ++ ioeGetErrorString e
    slen = lengthByte xs
    dlen = (5 * slen) `div` 8
{-# INLINEABLE decode #-}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
decodeToBuf
    :: (Show s1, ByteIndex s1, ByteArrayWrite a)
    => Int -> s1 -> a -> IO ()
decodeToBuf slen src dst = do
    let r = slen `mod` 8
        left = fail . ("Base32Hex.decode: " ++)
    unless (r `elem` [0, 2, 4, 5, 7]) $
        left $ "input has invalid length: " ++ show slen ++ " / " ++ show src
    loop left
  where
    fromHex32 w left right
        | _A <= w && w <= _V = right $ w - 55
        | _a <= w && w <= _v = right $ w - 87
        | _0 <= w && w <= _9 = right $ w - 48
        | otherwise = left $ "not base32hex format: " ++ show src

    store8 i v = unsafeWriteByte dst i v

    stores left ss n f0 f1 f2 f3 f4 f5 f6 f7 = do
        let w0 = f0 `unsafeShiftL` 3 .|. f1 `unsafeShiftR` 2
            w1 = f1 `unsafeShiftL` 6 .|. f2 `unsafeShiftL` 1 .|. f3 `unsafeShiftR` 4
            w2 = f3 `unsafeShiftL` 4 .|. f4 `unsafeShiftR` 1
            w3 = f4 `unsafeShiftL` 7 .|. f5 `unsafeShiftL` 2 .|. f6 `unsafeShiftR` 3
            w4 = f6 `unsafeShiftL` 5 .|. f7
            action
                | ss == (5 :: Int)  =
                               do { store8 n w0 ; store8 (n + 1) w1 ; store8 (n + 2) w2 ; store8 (n + 3) w3
                                  ; store8 (n + 4) w4 }
                | ss ==  4   = do { store8 n w0 ; store8 (n + 1) w1 ; store8 (n + 2) w2 ; store8 (n + 3) w3 }
                | ss ==  3   = do { store8 n w0 ; store8 (n + 1) w1 ; store8 (n + 2) w2 }
                | ss ==  2   = do { store8 n w0 ; store8 (n + 1) w1 }
                | ss ==  1   =      store8 n w0
                | otherwise  = left $ "internal error. illegal chunk length: " ++ show ss
        action

    loop left = go 0 0
      where
        fromH32 w = fromHex32 w left
        go ix ox
            | r >= 8     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                  fromH32 b4 $ \f4 -> fromH32 b5 $ \f5 -> fromH32 b6 $ \f6 -> fromH32 b7 $ \f7 ->
                      do { stores left 5 ox f0 f1 f2 f3 f4 f5 f6 f7 ; go (ix + 8) (ox + 5) }
            | r == 7     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                  fromH32 b4 $ \f4 -> fromH32 b5 $ \f5 -> fromH32 b6 $ \f6 ->
                           stores left 4 ox f0 f1 f2 f3 f4 f5 f6  0
            | r == 5     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                  fromH32 b4 $ \f4 ->
                           stores left 3 ox f0 f1 f2 f3 f4  0  0  0
            | r == 4     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                           stores left 2 ox f0 f1 f2 f3  0  0  0  0
            | r == 2     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 ->
                           stores left 1 ox f0 f1  0  0  0  0  0  0
            | r == 0     = pure ()
            | otherwise  = left $ "internal error. input has invalid length: " ++ show slen ++ " / " ++ show src
          where
            r = slen - ix
            ~b0 = src `unsafeIndexByte`  ix
            ~b1 = src `unsafeIndexByte` (ix + 1)
            ~b2 = src `unsafeIndexByte` (ix + 2)
            ~b3 = src `unsafeIndexByte` (ix + 3)
            ~b4 = src `unsafeIndexByte` (ix + 4)
            ~b5 = src `unsafeIndexByte` (ix + 5)
            ~b6 = src `unsafeIndexByte` (ix + 6)
            ~b7 = src `unsafeIndexByte` (ix + 7)

{-# INLINEABLE decodeToBuf #-}
{- FOURMOLU_ENABLE -}
