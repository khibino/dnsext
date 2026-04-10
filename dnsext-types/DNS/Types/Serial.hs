-- RFC 1982: Serial Number Arithmetic

module DNS.Types.Serial where

import Data.Word (Word32)

newtype Serial = Serial {unSerial :: Word32} deriving (Eq)

instance Show Serial where
    show (Serial n) = show n

instance Ord Serial where
    Serial s1 <= Serial s2 =
        s1 == s2
            || (s1 < s2 && (s2 - s1) < mx)
            || (s1 > s2 && (s1 - s2) > mx)
      where
        mx = 2 ^ (31 :: Int)
