{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module DNS.RRCache.MemSize () where

import GHC.Generics
import Data.Int (Int8, Int16, Int32, Int64)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SBS

import DNS.Types (ResourceRecord (..), RData (..))
import DNS.SEC (RD_RRSIG (..))

import DNS.RRCache.Types

{- NOTE:
RData includes type-class dictionary and existential type RD_*,
cannot generate Generic instance simply.

idea1:
* not compressed: cache result encoded ShortBytestring
* compressed: cache encoding function
 -}

deriving instance Generic Question
-- deriving instance Generic RData
deriving instance Generic RD_RRSIG
deriving instance Generic ResourceRecord
deriving instance Generic Positive
deriving instance Generic Negative
deriving instance Generic Ranking
deriving instance Generic Hit
deriving instance Generic Val

---

instance MemSize Question
instance MemSize ResourceRecord
instance MemSize Positive
instance MemSize Negative
instance MemSize Ranking
instance MemSize Hit
instance MemSize Val

---

wordSize :: Int
wordSize = 8

class MemSize a where
    getMemSize :: a -> Int

    default getMemSize :: (Generic a, GMemSize (Rep a)) => a -> Int
    getMemSize v = gMemSize (from v)

---

class GMemSize f where
    gMemSize :: f a -> Int

instance (GMemSize f, GMemSize g) => GMemSize (f :*: g) where
    gMemSize (x :*: y) = gMemSize x + gMemSize y

instance (GMemSize f, GMemSize g) => GMemSize (f :+: g) where
    gMemSize (L1 x) = gMemSize x
    gMemSize (R1 x) = gMemSize x

-- type constructor
instance GMemSize f => GMemSize (M1 D c f) where
    gMemSize (M1 x) = gMemSize x

-- data constructor
instance GMemSize f => GMemSize (M1 C c f) where
    gMemSize (M1 x) = wordSize {- data constuctor tag -}    + gMemSize x

-- data field
instance GMemSize f => GMemSize (M1 S c f) where
    gMemSize (M1 x) = wordSize {- pointer to data field -}  + gMemSize x

instance MemSize c => GMemSize (K1 i c) where
    gMemSize (K1 v) = getMemSize v

instance GMemSize U1 where
    gMemSize U1 = 0

-----

instance MemSize Int where
    getMemSize _ = wordSize

instance MemSize Word where
    getMemSize _ = wordSize

instance MemSize Int8 where
    getMemSize _ = 1

instance MemSize Int16 where
    getMemSize _ = 2

instance MemSize Int32 where
    getMemSize _ = 4

instance MemSize Int64 where
    getMemSize _ = 8

instance MemSize Word8 where
    getMemSize _ = 1

instance MemSize Word16 where
    getMemSize _ = 2

instance MemSize Word32 where
    getMemSize _ = 4

instance MemSize Word64 where
    getMemSize _ = 8

instance MemSize ByteString where
    getMemSize v = BS.length v

instance MemSize ShortByteString where
    getMemSize v = SBS.length v
