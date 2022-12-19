{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module VerifySpec (spec) where

import Test.Hspec

import Control.Monad (unless)
import Data.String (fromString)
import Data.Int
import Data.Word
import Data.ByteString (ByteString)

import Data.ByteArray.Encoding (Base (Base16, Base64), convertFromBase)

import DNS.Types
import qualified DNS.Types.Opaque as Opaque
import DNS.Types.Internal (decodeBase32Hex)

import DNS.SEC
import DNS.SEC.Verify

spec :: Spec
spec = do
  describe "KeyTag" $ do
    it "RFC5702 section6.1" $ caseKeyTag keyTagRFC5702
  describe "verify DS" $ do
    it "SHA1"   $ caseDS dsSHA1
    it "SHA256" $ caseDS dsSHA256
    it "SHA384" $ caseDS dsSHA384
  describe "verify RRSIG" $ do
    it "RSA/SHA256" $ caseRRSIG rsaSHA256
    it "RSA/SHA512" $ caseRRSIG rsaSHA512
    it "ECDSA/P256" $ caseRRSIG ecdsaP256
    it "ECDSA/P384" $ caseRRSIG ecdsaP384
    it "Ed25519"    $ caseRRSIG ed25519
    it "Ed448"      $ caseRRSIG ed448
  describe "NSEC3 hash" $ do
    it "RFC7129 section5" $ caseNSEC3Hash nsec3HashRFC7129
  describe "verify NSEC3" $ do
    it "NameError 1" $ caseNSEC3 nsec3RFC7129NameError
    it "NameError 2" $ caseNSEC3 nsec3RFC5155NameError
    it "NoData 1" $ caseNSEC3 nsec3RFC5155NoData1
    it "NoData 2" $ caseNSEC3 nsec3RFC5155NoData2
    it "NoData 3" $ caseNSEC3 nsec3RFC5155NoData3
    it "opt-out delegation" $ caseNSEC3 nsec3RFC5155OptOut
    it "wildcard expansion" $ caseNSEC3 nsec3RFC5155WildcardExpansion
    it "wildcard NoData" $ caseNSEC3 nsec3RFC5155WildcardNoData

-----
-- KeyTag cases

type KeyTag_Case = (ResourceRecord, Word16)

caseKeyTag :: KeyTag_Case -> Expectation
caseKeyTag (dnskeyRR, tag) = either expectationFailure (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  unless (keyTag dnskey == tag) $
    Left $ "caseKeyTag: keytag does not match: " ++ show (keyTag dnskey) ++ " =/= " ++ show tag
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-- example from https://datatracker.ietf.org/doc/html/rfc5702#section-6.1
keyTagRFC5702 :: KeyTag_Case
keyTagRFC5702 = (ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }, 9033)
  where
    key_rd = rd_dnskey' 256 3 8
             " AwEAAcFcGsaxxdgiuuGmCkVI \
             \ my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P \
             \ kxUdp6p/DlUmObdk= "

-----
-- DS cases

type DS_CASE = (ResourceRecord, ResourceRecord)

caseDS :: DS_CASE -> Expectation
caseDS (dnskeyRR, dsRR) = either expectationFailure (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  ds     <- takeRData "DS"     dsRR
  verifyDS (rrname dnskeyRR) dnskey ds
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-- exampe from  https://datatracker.ietf.org/doc/html/rfc4034#section-5.4
dsSHA1 :: DS_CASE
dsSHA1 =
  ( ResourceRecord { rrname = "dskey.example.com.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "dskey.example.com.", rrttl = 86400, rrclass = classIN, rrtype = DS, rdata = ds_rd }
  )
  where
    key_rd = rd_dnskey' 256 3 5
             " AQOeiiR0GOMYkDshWoSKz9Xz \
             \ fwJr1AYtsmx3TGkJaNXVbfi/ \
             \ 2pHm822aJ5iI9BMzNXxeYCmZ \
             \ DRD99WYwYqUSdjMmmAphXdvx \
             \ egXd/M5+X7OrzKBaMbCVdFLU \
             \ Uh6DhweJBjEVv5f2wwjM9Xzc \
             \ nOf+EPbtG9DMBmADjFDc2w/r \
             \ ljwvFw=="
    ds_rd = rd_ds' 60485 5 1
            " 2BB183AF5F22588179A53B0A \
            \ 98631FAD1A292118 "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.1
dsSHA256 :: DS_CASE
dsSHA256 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DS, rdata = ds_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 13
             " GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb \
             \ krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== "
    ds_rd = rd_ds' 55648 13 2
            " b4c8c1fe2e7477127b27115656ad6256f424625bf5c1 \
            \ e2770ce6d6e37df61d17 "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.2
dsSHA384 :: DS_CASE
dsSHA384 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DS, rdata = ds_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 14
             " xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1 \
             \ w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8 \
             \ /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 "
    ds_rd = rd_ds' 10771 14 4
            " 72d7b62976ce06438e9c0bf319013cf801f09ecc84b8 \
            \ d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94 \
            \ 6df983d6 "

-----
-- RRSIG cases

type RRSIG_CASE = (ResourceRecord, ResourceRecord, ResourceRecord)

caseRRSIG :: RRSIG_CASE -> Expectation
caseRRSIG (dnskeyRR, target, rrsigRR) = either expectationFailure (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  rrsig  <- takeRData "RRSIG"  rrsigRR
  verifyRRSIG dnskey rrsig target
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-- example from https://datatracker.ietf.org/doc/html/rfc5702#section-6.1
rsaSHA256 :: RRSIG_CASE
rsaSHA256 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 256 3 8
             " AwEAAcFcGsaxxdgiuuGmCkVI \
             \ my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P \
             \ kxUdp6p/DlUmObdk= "
    sig_rd = rd_rrsig' A 8 3 3600 1893456000 946684800 9033 "example.net."
             " kRCOH6u7l0QGy9qpC9 \
             \ l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa \
             \ cFYK/lPtPiVYP4bwg== "

-- example from https://datatracker.ietf.org/doc/html/rfc5702#section-6.2
rsaSHA512 :: RRSIG_CASE
rsaSHA512 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 256 3 10
             " AwEAAdHoNTOW+et86KuJOWRD \
             \ p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD \
             \ xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g \
             \ pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL "
    sig_rd = rd_rrsig' A 10 3 3600 1893456000 946684800 3740 "example.net."
             " tsb4wnjRUDnB1BUi+t \
             \ 6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa \
             \ eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL \
             \ DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw \
             \ = "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.1
ecdsaP256 :: RRSIG_CASE
ecdsaP256 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 13
             " GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb \
             \ krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== "
    sig_rd = rd_rrsig' A 13 3 3600 1284026679 1281607479 55648 "example.net."
             " qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA \
             \ yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.2
ecdsaP384 :: RRSIG_CASE
ecdsaP384 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 14
             " xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1 \
             \ w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8 \
             \ /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 "
    sig_rd = rd_rrsig' A 14 3 3600 1284027625 1281608425 10771 "example.net."
             " /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP \
             \ 95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz \
             \ WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm "

-- example from https://datatracker.ietf.org/doc/html/rfc8080#section-6.1
ed25519 :: RRSIG_CASE
ed25519 =
  ( ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd_mx 10 "mail.example.com." }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 15
             " l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= "
    sig_rd = rd_rrsig' MX 15 3 3600 1440021600 1438207200 3613 "example.com."
             " Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj \
             \ H5GaMWeG96GUVZu6ECKOQmemHDg== "

-- example from https://datatracker.ietf.org/doc/html/rfc8080#section-6.2
ed448 :: RRSIG_CASE
ed448 =
  ( ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd_mx 10 "mail.example.com." }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 16
             " 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx \
             \ 1FYYUcJKm1MDpJtIA "
    sig_rd = rd_rrsig' MX 16 3 3600 1440021600 1438207200 9713 "example.com."
             " Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3 \
             \ 9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0 \
             \ SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA "

-----
-- NSEC3 hash cases

type NSEC3Hash_CASE = ((RData, Domain), String)

caseNSEC3Hash :: NSEC3Hash_CASE -> Expectation
caseNSEC3Hash ((rd, domain), expectB32H) = either expectationFailure (const $ pure ()) $ do
  nsec3 <- maybe (Left $ "caseNSEC3Hash: not NSEC3: " ++ show rd) Right $ fromRData rd
  computed <- hashNSEC3 nsec3 domain
  check computed
  where
    expect = opaqueFromB32Hex expectB32H
    check computed
      | computed == expect  =  Right ()
      | otherwise           =  Left $ show computed ++ " =/= " ++ show expect

-- example from https://datatracker.ietf.org/doc/html/rfc7129#section-5
nsec3HashRFC7129 :: NSEC3Hash_CASE
nsec3HashRFC7129 =
  ( ( rd_nsec3' 1 0 2 "DEAD" "1AVVQN74SG75UKFVF25DGCETHGQ638EK" [NS, SOA, RRSIG, DNSKEY, NSEC3PARAM]
    , "example.org."
    )
  , "15bg9l6359f5ch23e34ddua6n1rihl9h"
  )

-----
-- NSEC3 cases

type NSEC3_ExpectW = (Domain, Domain) {- expect owner and qname -}
data NSEC3_Expect
  = N3W_NameError NSEC3_ExpectW NSEC3_ExpectW NSEC3_ExpectW
  | N3W_NoData NSEC3_ExpectW
  | N3W_OptOutDelegation NSEC3_ExpectW NSEC3_ExpectW
  | N3W_WildcardExpansion NSEC3_ExpectW
  | N3W_WildcardNoData NSEC3_ExpectW NSEC3_ExpectW NSEC3_ExpectW
  deriving (Eq, Show)
type NSEC3_CASE = (([(Domain, RData)], Domain, TYPE), NSEC3_Expect)

nsec3CheckResult :: NSEC3_Result -> NSEC3_Expect -> Either String ()
nsec3CheckResult result expect = case (result, expect) of
  (N3Result_NameError {..}, N3W_NameError ec en ew)               -> do
    check "name-error: closest"         (w2e nsec3_closest_match) ec
    check "name-error: next"            (w2e nsec3_next_closer_cover) en
    check "name-error: wildcard"        (w2e nsec3_wildcard_cover) ew
  (N3Result_NoData {..},    N3W_NoData ec)                        -> do
    check "no-data: closest"            (w2e nsec3_closest_match) ec
  (N3Result_OptOutDelegation {..}, N3W_OptOutDelegation ec en)    -> do
    check "opt-out: closest"            (w2e nsec3_closest_match) ec
    check "opt-out: next"               (w2e nsec3_next_closer_cover) en
  (N3Result_WildcardExpansion {..}, N3W_WildcardExpansion en)     -> do
    check "wildcard-expansion: next"    (w2e nsec3_next_closer_cover) en
  (N3Result_WildcardNoData {..},    N3W_WildcardNoData ec en ew)  -> do
    check "wildcard-no-data: closest"   (w2e nsec3_closest_match) ec
    check "wildcard-no-data: next"      (w2e nsec3_next_closer_cover) en
    check "wildcard-no-data: wildcard"  (w2e nsec3_wildcard_match) ew
  _                                                               ->
    Left $ unlines ["result data mismatch:", show result, show expect]

  where
    w2e :: NSEC3_Witness -> NSEC3_ExpectW
    w2e ((owner, _range), qname) = (owner, qname)
    check tag r e
      | r == e     =  Right ()
      | otherwise  =  Left $ tag ++ ": " ++ show r ++ " =/= " ++ show e

caseNSEC3 :: NSEC3_CASE -> Expectation
caseNSEC3 ((rds, qn, qtype), expect) = either expectationFailure (const $ pure ()) $ do
  result <- verifyNSEC3 ranges qn qtype
  nsec3CheckResult result expect
  where
    ranges = [ (owner, nsec3) | (owner, rd) <- rds, Just nsec3 <- [fromRData rd] ]

-- example from https://datatracker.ietf.org/doc/html/rfc7129#section-5.5
nsec3RFC7129NameError :: NSEC3_CASE
nsec3RFC7129NameError = ((rdatas, fromString "x.2.example.org.", TXT), expect)
  where
    rdatas =
      [ ("15bg9l6359f5ch23e34ddua6n1rihl9h.example.org.",
         rd_nsec3' 1 0 2 "DEAD" "1AVVQN74SG75UKFVF25DGCETHGQ638EK" [NS, SOA, RRSIG, DNSKEY, NSEC3PARAM])
      , ("1avvqn74sg75ukfvf25dgcethgq638ek.example.org.",
         rd_nsec3' 1 0 2 "DEAD" "75B9ID679QQOV6LDFHD8OCSHSSSB6JVQ" [])
      , ("75b9id679qqov6ldfhd8ocshsssb6jvq.example.org.",
         rd_nsec3' 1 0 2 "DEAD" "8555T7QEGAU7PJTKSNBCHG4TD2M0JNPJ" [TXT, RRSIG])
      ]
    expect =
      N3W_NameError
      ("15bg9l6359f5ch23e34ddua6n1rihl9h.example.org.", "example.org.")
      ("75b9id679qqov6ldfhd8ocshsssb6jvq.example.org.", "2.example.org.")
      ("1avvqn74sg75ukfvf25dgcethgq638ek.example.org.", "*.example.org.")

-- example from https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.1
-- Name Error
nsec3RFC5155NameError :: NSEC3_CASE
nsec3RFC5155NameError = ((rdatas, "a.c.x.w.example.", A), expect)
  where
    rdatas =
      [ ("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "2t7b4g4vsa5smi47k61mv5bv1a22bojr" [MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG])
      , ("b4um86eghhds6nea196smvmlo4ors995.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "gjeqe526plbf1g8mklp59enfd789njgi" [MX, RRSIG])
      , ("35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "b4um86eghhds6nea196smvmlo4ors995" [NS, DS, RRSIG])
      ]
    expect =
      N3W_NameError
      ("b4um86eghhds6nea196smvmlo4ors995.example.", "x.w.example.")
      ("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.", "c.x.w.example.")
      ("35mthgpgcu1qg68fab165klnsnk3dpvl.example.", "*.x.w.example")

-- example from https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.2
-- No Data Error
nsec3RFC5155NoData1 :: NSEC3_CASE
nsec3RFC5155NoData1 = ((rdatas, "ns1.example.", MX), expect)
  where
    rdatas =
      [ ("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "2vptu5timamqttgl4luu9kg21e0aor3s" [A, RRSIG])
      ]
    expect = N3W_NoData ("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.", "ns1.example.")

-- example from https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.2.1
-- No Data Error, Empty Non-Terminal
nsec3RFC5155NoData2 :: NSEC3_CASE
nsec3RFC5155NoData2 = ((rdatas, "y.w.example.", A), expect)
  where
    rdatas =
      [ ("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.",
        rd_nsec3' 1 1 12 "aabbccdd" "k8udemvp1j2f7eg6jebps17vp3n8i58h" [])
      ]
    expect = N3W_NoData ("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.", "y.w.example.")

-- example from https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.6
-- DS Child Zone No Data Error
nsec3RFC5155NoData3 :: NSEC3_CASE
nsec3RFC5155NoData3 = ((rdatas, "example.", DS), expect)
  where
    rdatas =
      [ ("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "2t7b4g4vsa5smi47k61mv5bv1a22bojr" [MX, DNSKEY, NS])
      ]
    expect = N3W_NoData ("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.", "example.")

-- example from https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.3
-- Referral to an Opt-Out Unsigned Zone
nsec3RFC5155OptOut :: NSEC3_CASE
nsec3RFC5155OptOut = ((rdatas, "mc.c.example.", MX), expect)
  where
    rdatas =
      [ ("35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "b4um86eghhds6nea196smvmlo4ors995" [NS, DS, RRSIG])
      , ("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "2t7b4g4vsa5smi47k61mv5bv1a22bojr" [MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG])
      ]
    expect =
      N3W_OptOutDelegation
      ("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.", "example.")
      ("35mthgpgcu1qg68fab165klnsnk3dpvl.example.", "c.example.")

-- example from https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.4
-- Wildcard Expansion
nsec3RFC5155WildcardExpansion :: NSEC3_CASE
nsec3RFC5155WildcardExpansion = ((rdatas, "a.z.w.example.", MX), expect)
  where
    rdatas =
      [ ("q04jkcevqvmu85r014c7dkba38o0ji5r.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "r53bq7cc2uvmubfu5ocmm6pers9tk9en" [A, RRSIG])
      ]
    expect = N3W_WildcardExpansion ("q04jkcevqvmu85r014c7dkba38o0ji5r.example.", "z.w.example.")


-- example from https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.5
-- Wildcard No Data Error
nsec3RFC5155WildcardNoData :: NSEC3_CASE
nsec3RFC5155WildcardNoData = ((rdatas, "a.z.w.example.", AAAA), expect)
  where
    rdatas =
      [ ("k8udemvp1j2f7eg6jebps17vp3n8i58h.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "kohar7mbb8dc2ce8a9qvl8hon4k53uhi" [])
      , ("q04jkcevqvmu85r014c7dkba38o0ji5r.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "r53bq7cc2uvmubfu5ocmm6pers9tk9en" [A, RRSIG])
      , ("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.",
         rd_nsec3' 1 1 12 "aabbccdd" "t644ebqk9bibcna874givr6joj62mlhv" [MX, RRSIG])
      ]
    expect =
      N3W_WildcardNoData
      ("k8udemvp1j2f7eg6jebps17vp3n8i58h.example.", "w.example.")
      ("q04jkcevqvmu85r014c7dkba38o0ji5r.example.", "z.w.example.")
      ("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.", "*.w.example")

-----
-- helpers

rd_dnskey' :: Word16 -> Word8 -> Word8 -> String -> RData
rd_dnskey' kflags proto walg pubkey = rd_dnskey (toDNSKEYflags kflags) proto alg $ toPubKey alg $ opaqueFromB64 pubkey
  where
    alg = toPubAlg walg

rd_ds' :: Word16 -> Word8 -> Word8 -> String -> RData
rd_ds' keytag pubalg digalg digest = rd_ds keytag (toPubAlg pubalg) (toDigestAlg digalg) (opaqueFromB16Hex digest)

rd_rrsig' :: TYPE -> Word8 -> Word8 -> TTL -> Int64 -> Int64 -> Word16 -> String -> String -> RData
rd_rrsig' typ alg a b c d e dom = rd_rrsig typ (toPubAlg alg) a b c d e (fromString dom) . opaqueFromB64

rd_nsec3' :: Word8 -> Word8 -> Word16 -> String -> String -> [TYPE] -> RData
rd_nsec3' alg fs i salt next = rd_nsec3 (toHashAlg alg) (toNSEC3flags fs) i (opaqueFromB16Hex salt) (opaqueFromB32Hex next)

opaqueFromB16Hex :: String -> Opaque
opaqueFromB16Hex =
  either (error "opaqueFromB16Hex: fail to decode hex") Opaque.fromByteString .
  convertFromBase Base16 . (fromString :: String -> ByteString) . filter (/= ' ')

opaqueFromB32Hex :: String -> Opaque
opaqueFromB32Hex =
  either (error "opaqueFromB32Hex: fail to decode base32hex") Opaque.fromByteString .
  decodeBase32Hex . (fromString :: String -> ByteString) . filter (/= ' ')

opaqueFromB64 :: String -> Opaque
opaqueFromB64 =
  either (error "opaqueFromB64: fail to decode base64") Opaque.fromByteString .
  convertFromBase Base64 . (fromString :: String -> ByteString) . filter (/= ' ')
