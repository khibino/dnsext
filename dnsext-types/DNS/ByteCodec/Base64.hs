module DNS.ByteCodec.Base64 where

-- GHC packages
import Control.Monad
import Data.Bits
import System.IO.Unsafe (unsafePerformIO)

-- this package
import DNS.ByteCodec.Type (ByteArrayWrite (..), ByteIndex (..), ByteWriter (..))

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> :seti -XTypeApplications
-- >>> import Data.ByteString (ByteString)
-- >>> import Data.ByteString.Short (ShortByteString)
-- >>> type BS = ByteString
-- >>> type SBS = ShortByteString

encode
    :: (ByteIndex s1, ByteWriter s2 a)
    => s1  -- ^ input bytes
    -> s2  -- ^ base32hex output bytes
encode xs =
    unsafePerformIO $ unsafeCreateBytes dlen (encodeToBuf slen xs)
    {- Original bytestring executes `unsafeDuperblePerformIO` without `noDuplicate` checks.
       Is rearly safe with updating buffer by more than one thread? -}
  where
    slen = lengthByte xs
    dlen = (8 * slen + 4) `div` 5
{-# INLINEABLE encode #-}

encodeToBuf = undefined
