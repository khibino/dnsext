-- RFC 1982: Serial Number Arithmetic

module DNS.Types.Serial where

import Data.Word (Word32, Word8)

newtype Serial = Serial {unSerial :: Word32} deriving (Eq)

instance Show Serial where
    show (Serial n) = show n

instance Semigroup Serial where
    Serial i1 <> Serial i2 = Serial (i1 + i2)

instance Ord Serial where
    Serial i1 <= Serial i2 =
        i1 == i2
            || (i1 < i2 && (i2 - i1) < mx)
            || (i1 > i2 && (i1 - i2) > mx)
      where
        mx = 2 ^ (31 :: Int)

newtype Serial8 = Serial8 {unSerial8 :: Word8} deriving (Eq)

instance Show Serial8 where
    show (Serial8 n) = show n

-- | Addition
--
-- >>> Serial8 255 <> Serial8 1
-- 0
-- >>> Serial8 100 <> Serial8 100
-- 200
-- >>> Serial8 200 <> Serial8 100
-- 44
instance Semigroup Serial8 where
    Serial8 i1 <> Serial8 i2 = Serial8 (i1 + i2)

-- | Comparison
-- >>> Serial8 1 > Serial8 0
-- True
-- >>> Serial8 44 > Serial8 0
-- True
-- >>> Serial8 100 > Serial8 0
-- True
-- >>> Serial8 100 > Serial8 44
-- True
-- >>> Serial8 200 > Serial8 100
-- True
-- >>> Serial8 255 > Serial8 200
-- True
-- >>> Serial8 0 > Serial8 255
-- True
-- >>> Serial8 100 > Serial8 255
-- True
-- >>> Serial8 0 > Serial8 200
-- True
-- >>> Serial8 44 > Serial8 200
-- True
instance Ord Serial8 where
    Serial8 i1 <= Serial8 i2 =
        i1 == i2
            || (i1 < i2 && (i2 - i1) < mx)
            || (i1 > i2 && (i1 - i2) > mx)
      where
        mx = 2 ^ (7 :: Int)
