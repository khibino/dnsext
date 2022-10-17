{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.RRSIG (
    rsaPubKeyFromDNSKEY
  , decodeRRSIG'
  , decodeRRSIG
  , computeRRSIG
  , verifyRRSIG
  ) where

-- GHC packages
import qualified  Data.ByteString as BS

-- memory
import qualified Data.ByteArray as BA
import Data.ByteArray.Encoding (Base (Base16), convertToBase)

-- cryptonite
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.RSA (PublicKey(..))
import Crypto.PubKey.RSA.Prim (ep)
import Crypto.Hash (hashWith)
import Crypto.Hash.Algorithms (SHA1(..), SHA256(..), SHA512(..))

-- dnsext-types
import DNS.Types
import DNS.Types.Internal

-- this package
import DNS.SEC.Imports
import DNS.SEC.Time
import DNS.SEC.Types (RD_RRSIG(..), RD_DNSKEY(..))

{- RSA Public KEY Resource Records
   RFC3110 section2 https://datatracker.ietf.org/doc/html/rfc3110#section-2 -}
takePubKeyRSA :: ByteString -> Maybe PublicKey
takePubKeyRSA kbs = mkKey . getKeyExp <$> BS.uncons kbs
  where
    mkKey (ex, key) = PublicKey { public_size = BS.length key, public_n = os2ip key, public_e = os2ip ex }
    getKeyExp (b1, rest)
      | b1 > 0                        =
          BS.splitAt (fromIntegral b1) rest
      | otherwise {- case b1 == 0 -}  =
          BS.splitAt (fromIntegral $ os2ip exlen) rest2
      where (exlen, rest2) = BS.splitAt 2 rest

rsaPubKeyFromDNSKEY :: RD_DNSKEY -> Either String PublicKey
rsaPubKeyFromDNSKEY dk =
  maybe (Left "Verify.takePubKeyRSA: empty input") Right
  $ takePubKeyRSA $ opaqueToByteString $ dnskey_public_key dk

{-
-- Domain Name System Security (DNSSEC) Algorithm Numbers
-- https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml

Number    Description                      Mnemonic              Zone Signing   Trans. Sec.   Reference

0         Delete DS                        DELETE                N              N             [RFC4034][proposed standard][RFC4398][proposed standard][RFC8078][proposed standard]
1         RSA/MD5 (deprecated)             RSAMD5                N              Y             [RFC3110][proposed standard][RFC4034][proposed standard]
2         Diffie-Hellman                   DH                    N              Y             [RFC2539][proposed standard]
3         DSA/SHA1                         DSA                   Y              Y             [RFC3755][proposed standard][RFC2536][proposed standard]
4         Reserved                                                                            [RFC6725][proposed standard]
5         RSA/SHA-1                        RSASHA1               Y              Y             [RFC3110][proposed standard][RFC4034][proposed standard]
6         DSA-NSEC3-SHA1                   DSA-NSEC3-SHA1        Y              Y             [RFC5155][proposed standard]
7         RSASHA1-NSEC3-SHA1               RSASHA1-NSEC3-SHA1    Y              Y             [RFC5155][proposed standard]
8         RSA/SHA-256                      RSASHA256             Y              *             [RFC5702][proposed standard]
9         Reserved                                                                            [RFC6725][proposed standard]
10        RSA/SHA-512                      RSASHA512             Y              *             [RFC5702][proposed standard]
11        Reserved                                                                            [RFC6725][proposed standard]
12        GOST R 34.10-2001                ECC-GOST              Y              *             [RFC5933][proposed standard]
13        ECDSA Curve P-256 with SHA-256   ECDSAP256SHA256       Y              *             [RFC6605][proposed standard]
14        ECDSA Curve P-384 with SHA-384   ECDSAP384SHA384       Y              *             [RFC6605][proposed standard]
15        Ed25519                          ED25519               Y              *             [RFC8080][proposed standard]
16        Ed448                            ED448                 Y              *             [RFC8080][proposed standard]
17-122    Unassigned
123-251   Reserved                                                                            [RFC4034][proposed standard][RFC6014][proposed standard]
252       Reserved for Indirect Keys       INDIRECT              N              N             [RFC4034][proposed standard]
253       private algorithm                PRIVATEDNS            Y              Y             [RFC4034][proposed standard]
254       private algorithm OID            PRIVATEOID            Y              Y             [RFC4034][proposed standard]
255       Reserved                                                                            [RFC4034][proposed standard]
 -}
decodeRRSIG' :: PublicKey -> RD_RRSIG -> Either String ByteString
decodeRRSIG' pubkey RD_RRSIG{..} =
  stripRRSigPrefix $ ep pubkey (opaqueToByteString rrsig_value)
  where
    stripRRSigPrefix :: ByteString -> Either String ByteString
    stripRRSigPrefix  s0 = do
      s1 <- stripP (BS.pack [0x00, 0x01]) s0
      let s2 = BS.dropWhile (== 0xff) s1
      s3 <- stripP (BS.pack [0x00]) s2
      pkcs1 <- getPkcs1Prefix
      stripP pkcs1 s3
        where
          stripP prefix = maybe (Left $ "decodeRRSIG.stripRRSigPrefix: expected prefix " ++ show prefix) Right . BS.stripPrefix prefix

    getPkcs1Prefix = case rrsig_key_alg of
      5   ->  Right sha1
      8   ->  Right sha256
      10  ->  Right sha512
      _   ->  Left $ "decodeRRSIG: unknown PKCS1 for algorithm: " ++ show rrsig_key_alg

    {-
    -- PKCS for RSA/SHA-XXX
    -- https://datatracker.ietf.org/doc/html/rfc8017#section-9.2

         SHA-1:       (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
         SHA-224:     (0x)30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c || H.
         SHA-256:     (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
         SHA-384:     (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
         SHA-512:     (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
     -}
    sha1    = BS.pack [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]
    -- sha224  = BS.pack [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]
    sha256  = BS.pack [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
    -- sha384  = BS.pack [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
    sha512  = BS.pack [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]

decodeRRSIG :: RD_DNSKEY -> RD_RRSIG -> Either String ByteString
decodeRRSIG dnskey rrsig = do
  when (dnskey_algorithm dnskey /= rrsig_key_alg rrsig) $
    Left $ "decodeRRSIG: key algorithm mismatch: " ++
    show (dnskey_algorithm dnskey) ++ " /= " ++ show (rrsig_key_alg rrsig)
  pubkey <- rsaPubKeyFromDNSKEY dnskey
  decodeRRSIG' pubkey rrsig

-----

putRRSIGHeader :: RD_RRSIG -> SPut
putRRSIGHeader RD_RRSIG{..} =
  mconcat [ put16 $ fromTYPE rrsig_type
          , put8    rrsig_key_alg
          , put8    rrsig_num_labels
          , put32   rrsig_ttl
          , putDnsTime rrsig_expiration
          , putDnsTime rrsig_inception
          , put16   rrsig_key_tag
          , putDomain Canonical rrsig_zone
          ]

computeRRSIG :: RD_RRSIG -> ResourceRecord -> Either String ByteString
computeRRSIG rrsig rr = do
  hashF <- getHashF
  Right $ hashF $ runSPut $ putRRSIGHeader rrsig <> putResourceRecord Canonical rr
  where
    hashWith' alg = BA.pack . BA.unpack . hashWith alg
    getHashF = case rrsig_key_alg rrsig of
      5   ->  Right $ hashWith' SHA1
      8   ->  Right $ hashWith' SHA256
      10  ->  Right $ hashWith' SHA512
      x   ->  Left $ "computeRRSIGvalue: unknown algorithm map: " ++ show x

-----

verifyRRSIG :: RD_DNSKEY -> RD_RRSIG -> ResourceRecord -> Either String ByteString
verifyRRSIG dnskey rrsig rr = do
  decodedSig   <- decodeRRSIG dnskey rrsig
  computedSig  <- computeRRSIG rrsig rr
  let hex = convertToBase Base16 :: ByteString -> ByteString
  when (decodedSig /= computedSig) $ Left $
    unlines [ "verifyRRSIG: signature miss-match:"
            , show $ hex decodedSig
            , "=/="
            , show $ hex computedSig ]
  return computedSig
