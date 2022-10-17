
import Data.String (fromString)
import Data.Word
import Data.ByteString (ByteString)

-- memory
import Data.ByteArray.Encoding (Base (Base64), convertFromBase)

import DNS.Types
import qualified DNS.Types.Opaque as Opaque
import DNS.SEC
import DNS.SEC.PubKey

import DNS.SEC.Verify


opaqueFromB64' :: String -> Opaque
opaqueFromB64' =
  either (error "opaqueFromB64': fail to decode base64") Opaque.fromByteString .
  convertFromBase Base64 . (fromString :: String -> ByteString) . filter (/= ' ')

rd_dnskey' :: Word16 -> Word8 -> Word8 -> String -> RData
rd_dnskey' kflags proto walg pubkey = rd_dnskey (toDNSKEYflags kflags) proto alg $ toPubKey alg $ opaqueFromB64' pubkey
  where
    alg = toPubAlg walg

-- example from RFC 5702

--    example.net.     3600  IN  DNSKEY  (256 3 8 AwEAAcFcGsaxxdgiuuGmCkVI
--                     my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
--                     kxUdp6p/DlUmObdk= );{id = 9033 (zsk), size = 512b}
dnskeyExample :: ResourceRecord
dnskeyExample = ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 256 3 8
         "AwEAAcFcGsaxxdgiuuGmCkVI my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P kxUdp6p/DlUmObdk="

--    www.example.net. 3600  IN  A  192.0.2.91
rrExample :: ResourceRecord
rrExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }

--    www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
--                      20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
--                      l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
--                      cFYK/lPtPiVYP4bwg==);{id = 9033}
rrsigExample :: ResourceRecord
rrsigExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig A (toPubAlg 8) 3 3600 1893456000 946684800 9033 (fromString "example.net.")
         (opaqueFromB64' "kRCOH6u7l0QGy9qpC9 l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa cFYK/lPtPiVYP4bwg==")

verifyExample :: Either String ()
verifyExample = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample
  rrsig  <- getRData "RRSIG"  rrsigExample
  verifyRRSIG dnskey rrsig rrExample

dnskeyExample2 :: ResourceRecord
dnskeyExample2 = ResourceRecord { rrname = fromString "iij.ad.jp.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 256 3 8
         "AwEAAeD+V7UXu0mzGaIRtZryR7qz/+evt1GX+pZJVgcVC9n67c8dzrv3 YrIuNUlRVKTOKcTOuwA6/I3oo5P/j+zTKzusqa9MyJuIXFzROsJ2kjCV KFVxB+L+rfQxhO+334fmFFehPouDew2kAPP6YKDufkkMwSfj/VUooXoN rqr42o97"

rrExample2 :: ResourceRecord
rrExample2 = ResourceRecord { rrname = fromString "eng-blog.iij.ad.jp.", rrttl = 300, rrclass = classIN, rrtype = A, rdata = rd_a $ read "202.232.2.183" }

rrsigExample2 :: ResourceRecord
rrsigExample2 = ResourceRecord { rrname = fromString "eng-blog.iij.ad.jp.", rrttl = 300, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig A (toPubAlg 8) 4 300 1667401805 1664809805 34908 (fromString "iij.ad.jp.")
         (opaqueFromB64' "QEv8fD6+zGWJxVRwXN/4OQP/fJWjb8+zeKugVYdvGClgrFssNUTcx8SU yoPbRrW+xqZePxp7i1yGfBapZVq94mCR/x9W88gT5zl0pZ+pAAbfmg9a WD+/UU+27MgJxZFdHXIxBHSvoDHxsA4RihACCT9drk+Sueg2MbbwU38d dGM=")

verifyExample2 :: Either String ()
verifyExample2 = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample2
  rrsig  <- getRData "RRSIG"  rrsigExample2
  verifyRRSIG dnskey rrsig rrExample2
