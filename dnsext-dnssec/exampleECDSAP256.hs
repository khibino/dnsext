
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

--    example.net. 3600 IN DNSKEY 257 3 13 (
--            GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
--            krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )
dnskeyExample :: ResourceRecord
dnskeyExample = ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 257 3 13
         "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="

--    www.example.net. 3600 IN A 192.0.2.1
rrExample :: ResourceRecord
rrExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }

--    www.example.net. 3600 IN RRSIG A 13 3 3600 (
--            20100909100439 20100812100439 55648 example.net.
--            qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
--            yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )
rrsigExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig A (toPubAlg 13) 3 3600 1284026679 1281607479 55648 (fromString "example.net.")
         (opaqueFromB64' "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==")

verifyExample :: Either String ()
verifyExample = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample
  rrsig  <- getRData "RRSIG"  rrsigExample
  verifyRRSIG dnskey rrsig rrExample

-- salesforce.com.    3600  IN  DNSKEY  256 3 13
-- Y2q4vpoBYkeRbvsDMzpEJs10GEPEtu90hlAVIlD9XD8nnpcEM4WOVBgR 0/fOjavvw5mkwrgHb1nylySNNthBag==
dnskeyExample2 :: ResourceRecord
dnskeyExample2 = ResourceRecord { rrname = fromString "salesforce.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 256 3 13
         "Y2q4vpoBYkeRbvsDMzpEJs10GEPEtu90hlAVIlD9XD8nnpcEM4WOVBgR 0/fOjavvw5mkwrgHb1nylySNNthBag=="

-- help.salesforce.com.  300  IN  CNAME  help.salesforce.com.00d30000000xsfgeas.live.siteforce.com.
rrExample2 :: ResourceRecord
rrExample2 =
  ResourceRecord
  { rrname = fromString "help.salesforce.com.", rrttl = 300, rrclass = classIN, rrtype = CNAME
  , rdata = rd_cname $ fromString "help.salesforce.com.00d30000000xsfgeas.live.siteforce.com." }

-- help.salesforce.com.  300  IN  RRSIG  CNAME 13 3 300 20221201204626 20221002201307 2317 salesforce.com.
-- +CGXyQkuElGNc7FpDa0sO0ya7x/B/7DGhRfKOWSBGgshlokxUukOJHz2 T7+xdoNv2mpS2bTOK5LpJY2FS9e3kQ==
rrsigExample2 :: ResourceRecord
rrsigExample2 =
  ResourceRecord
  { rrname = fromString "help.salesforce.com.", rrttl = 300, rrclass = classIN, rrtype = RRSIG, rdata = rd  }
  where
    rd = rd_rrsig CNAME (toPubAlg 13) 3 300 1669927586 1664741587 2317 (fromString "salesforce.com.")
         (opaqueFromB64' "+CGXyQkuElGNc7FpDa0sO0ya7x/B/7DGhRfKOWSBGgshlokxUukOJHz2 T7+xdoNv2mpS2bTOK5LpJY2FS9e3kQ==")

verifyExample2 :: Either String ()
verifyExample2 = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample2
  rrsig  <- getRData "RRSIG"  rrsigExample2
  verifyRRSIG dnskey rrsig rrExample2
