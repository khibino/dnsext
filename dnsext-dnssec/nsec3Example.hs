{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

import Data.Char (toLower)
import Data.String (fromString)
import qualified Data.ByteString.Char8 as B8
import Data.ByteString.Short (toShort)

import DNS.Types
import qualified DNS.Types.Opaque as Opaque

import DNS.SEC.Imports

import DNS.SEC
-- import DNS.SEC.Verify.N3SHA (n3sha1)
import DNS.SEC.Verify


toB32 :: Opaque -> ShortByteString
toB32 = toShort . B8.map toLower . Opaque.toBase32Hex

fromB32 :: String -> Either String Opaque
fromB32 = either (Left . show) Right . Opaque.fromBase32Hex . fromString

fromB32' :: String -> Opaque
fromB32' = either error id . fromB32

fromB16 :: String -> Either String Opaque
fromB16 = Opaque.fromBase16 . B8.pack

fromB16' :: String -> Opaque
fromB16' = either error id . fromB16

checkNSEC3 :: (Domain, RData) -> Domain -> IO ()
checkNSEC3 (hashed, n3rd) owner = do
  nsec3 <- either fail return $ takeRData "NSEC3" n3rd
  computed <- either fail return $ hashNSEC3 nsec3 owner
  (expect, _) <- maybe (fail "no zoned domain") return $ unconsName hashed
  if toB32 computed == expect
    then putStrLn "Good"
    else do
    putStr $ unlines
      [ "Bad"
      , unwords [show computed, "=/=", show expect ]
      ]
    fail "computed hash mismatch!"

  where
    takeRData name rd = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd

    unconsName :: Domain -> Maybe (ShortByteString, Domain)
    unconsName name = case toWireLabels name of
      x:xs ->  Just (x, fromWireLabels xs)
      []   ->  Nothing

rd_nsec3' :: Word8 -> Word8 -> Word16 -> String -> String -> [TYPE] -> RData
rd_nsec3' alg fs i salt next = rd_nsec3 (toHashAlg alg) (toNSEC3flags fs) i (fromB16' salt) (fromB32' next)

-- from RFC 7129
{-
example.org

   15bg9l6359f5ch23e34ddua6n1rihl9h.example.org. (
      NSEC3 1 0 2 DEAD A6EDKB6V8VL5OL8JNQQLT74QMJ7HEB84
           NS SOA RRSIG DNSKEY NSEC3PARAM )
 -}
rfc7129_example_org :: (Domain, RData)
rfc7129_example_org =
  ("15bg9l6359f5ch23e34ddua6n1rihl9h.example.org.",
   rd_nsec3' 1 0 2 "DEAD" "A6EDKB6V8VL5OL8JNQQLT74QMJ7HEB84" [NS, SOA, RRSIG, DNSKEY, NSEC3PARAM])

check0 :: IO ()
check0 = checkNSEC3 rfc7129_example_org "example.org"

result0 :: Either String ShortByteString
result0 = do
  nsec3 <- maybe (Left $ "not NSEC3: " ++ show rd) Right $ fromRData rd
  computed <- hashNSEC3 nsec3 "example.org"
  return $ toB32 computed
  where
    (_, rd) = rfc7129_example_org

expect0 :: ShortByteString
expect0 = "15bg9l6359f5ch23e34ddua6n1rihl9h"

-- from RFC 5155
{-
x.y.w.example

   2vptu5timamqttgl4luu9kg21e0aor3s.example. NSEC3 1 1 12 aabbccdd (
                          35mthgpgcu1qg68fab165klnsnk3dpvl MX RRSIG )
 -}
rfc5155_xyw_examle :: (Domain, RData)
rfc5155_xyw_examle =
  ("2vptu5timamqttgl4luu9kg21e0aor3s.example.",
   rd_nsec3' 1 1 12 "aabbccdd" "35mthgpgcu1qg68fab165klnsnk3dpvl" [MX, RRSIG])

check1 :: IO ()
check1 = checkNSEC3 rfc5155_xyw_examle "x.y.w.example"

result1 :: Either String ShortByteString
result1 = do
  nsec3 <- maybe (Left $ "not NSEC3: " ++ show rd) Right $ fromRData rd
  computed <- hashNSEC3 nsec3 "x.y.w.example"
  return $ toB32 computed
  where
    (_, rd) = rfc5155_xyw_examle

expect1 :: ShortByteString
expect1 = "2vptu5timamqttgl4luu9kg21e0aor3s"

-- NSEC3 Flag check
{- https://datatracker.ietf.org/doc/html/rfc5155#section-8.2
   "A validator MUST ignore NSEC3 RRs with a Flag fields value other than zero or one." -}

-- NSEC3PARAM Flag check
{- https://datatracker.ietf.org/doc/html/rfc5155#section-4.1.2
   "NSEC3PARAM RRs with a Flags field value other than zero MUST be ignored." -}

-- Terminology: Hash order
{- base32hex does not change hash ordering.
   https://datatracker.ietf.org/doc/html/rfc5155#section-1.3
   "Note that this order is the same as the canonical DNS name order specified in [RFC4034],
    when the hashed owner names are in base32, encoded with an Extended Hex Alphabet [RFC4648]." -}

from16to32 :: String -> ByteString
from16to32 = Opaque.toBase32Hex . fromB16'

from16to32L :: String -> ByteString
from16to32L = B8.map toLower . from16to32

-- "8e683ad10eaba1da77c481fe23663f455dfefc7f"
