-- RFC 1982: Serial Number Arithmetic

module DNS.Types.Serial where

import Data.Word (Word32, Word64)

newtype Serial = Serial {unSerial :: Word32} deriving (Eq)

instance Show Serial where
    show (Serial n) = show n

instance Ord Serial where
    Serial s1 <= Serial s2 =
        s1 == s2
            || (i1 < i2 && i2 - i1 < mx)
            || (i1 > i2 && i1 - i2 > mx)
      where
        i1 :: Word64
        i1 = fromIntegral s1
        i2 :: Word64
        i2 = fromIntegral s2
        mx = 2 ^ (31 :: Int)
