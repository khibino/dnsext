
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

-- example.com. 3600 IN DNSKEY 257 3 16 (
--              3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx
--              1FYYUcJKm1MDpJtIA )
dnskeyExample :: ResourceRecord
dnskeyExample = ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 257 3 16
         "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx 1FYYUcJKm1MDpJtIA"

-- example.com. 3600 IN MX 10 mail.example.com.
rrExample :: ResourceRecord
rrExample = ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd }
  where
    rd = rd_mx 10 (fromString "mail.example.com.")

-- example.com. 3600 IN RRSIG MX 3 3600 (
--              1440021600 1438207200 9713 example.com. (
--              Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3
--              9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0
--              SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA )
rrsigExample :: ResourceRecord
rrsigExample = ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig MX (toPubAlg 16) 3 3600 1440021600 1438207200 9713 (fromString "example.com.")
         (opaqueFromB64' "Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3 9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0 SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA")

verifyExample :: Either String ()
verifyExample = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample
  rrsig  <- getRData "RRSIG"  rrsigExample
  verifyRRSIG dnskey rrsig rrExample
