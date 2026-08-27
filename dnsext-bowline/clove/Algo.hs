module Algo where

import DNS.SEC

{- FOURMOLU_DISABLE -}
toPubAlgo :: String -> Maybe PubAlg
toPubAlgo "RSASHA1"            = Just RSASHA1
toPubAlgo "RSASHA1-NSEC3-SHA1" = Just RSASHA1_NSEC3_SHA1
toPubAlgo "RSASHA256"          = Just RSASHA256
toPubAlgo "RSASHA512"          = Just RSASHA512
toPubAlgo "ECDSAP256SHA256"    = Just ECDSAP256SHA256
toPubAlgo "ECDSAP384SHA384"    = Just ECDSAP384SHA384
toPubAlgo "ED25519"            = Just ED25519
toPubAlgo "ED448"              = Just ED448
toPubAlgo _                    = Nothing

toDsDigest :: String -> Maybe DigestAlg
toDsDigest "SHA1"    = Just SHA1
toDsDigest "SHA-1"   = Just SHA1
toDsDigest "SHA256"  = Just SHA256
toDsDigest "SHA-256" = Just SHA256
toDsDigest "SHA384"  = Just SHA384
toDsDigest "SHA-384" = Just SHA384
toDsDigest _         = Nothing

toNsec3Hash :: String -> Maybe HashAlg
toNsec3Hash "SHA1"  = Just Hash_SHA1
toNsec3Hash "SHA-1" = Just Hash_SHA1
toNsec3Hash _       = Nothing
{- FOURMOLU_ENABLE -}
