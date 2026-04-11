-- RFC 1982: Serial Number Arithmetic

module DNS.Types.Serial where

import Data.Word (Word32)

newtype Serial = Serial {unSerial :: Word32} deriving (Eq)

instance Show Serial where
    show (Serial n) = show n

instance Ord Serial where
    Serial i1 <= Serial i2 =
        i1 == i2
            || (i1 < i2 && (i2 - i1) < mx)
            || (i1 > i2 && (i1 - i2) > mx)
      where
        mx = 2 ^ (31 :: Int)
