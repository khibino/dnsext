
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

import GHC.Exts


opaqueFromB64' :: String -> Opaque
opaqueFromB64' =
  either (error "opaqueFromB64': fail to decode base64") Opaque.fromByteString .
  convertFromBase Base64 . (fromString :: String -> ByteString) . filter (/= ' ')

rd_dnskey' :: Word16 -> Word8 -> Word8 -> String -> RData
rd_dnskey' kflags proto walg pubkey = rd_dnskey (toDNSKEYflags kflags) proto alg $ toPubKey alg $ opaqueFromB64' pubkey
  where
    alg = toPubAlg walg

--    example.net.    3600  IN  DNSKEY  (256 3 10 AwEAAdHoNTOW+et86KuJOWRD
--                    p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
--                    xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
--                    pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL
--                    );{id = 3740 (zsk), size = 1024b}
dnskeyExample = ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 256 3 10
         "AwEAAdHoNTOW+et86KuJOWRD p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"

--    www.example.net. 3600  IN  A  192.0.2.91
rrExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }

--    www.example.net. 3600  IN  RRSIG  (A 10 3 3600 20300101000000
--                     20000101000000 3740 example.net. tsb4wnjRUDnB1BUi+t
--                     6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
--                     eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
--                     DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
--                     =);{id = 3740}
rrsigExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig A (toPubAlg 10) 3 3600 1893456000 946684800 3740 (fromString "example.net.")
         (opaqueFromB64' "tsb4wnjRUDnB1BUi+t 6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw =")

verifyExample :: Either String ()
verifyExample = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample
  rrsig  <- getRData "RRSIG"  rrsigExample
  verifyRRSIG dnskey rrsig rrExample

-- runWithCS :: HasCallStack => Either String () -> IO ()
-- runWithCS e = do
--   either
