
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

-- example.com. 3600 IN DNSKEY 257 3 15 (
--              l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )
dnskeyExample :: ResourceRecord
dnskeyExample = ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 257 3 15
         "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="

-- example.com. 3600 IN MX 10 mail.example.com.
rrExample :: ResourceRecord
rrExample = ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd }
  where
    rd = rd_mx 10 (fromString "mail.example.com.")

-- example.com. 3600 IN RRSIG MX 3 3600
--              1440021600 1438207200 3613 example.com.
--              ( Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj H5GaMWeG96GUVZu6ECKOQmemHDg== )
rrsigExample :: ResourceRecord
rrsigExample = ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig MX (toPubAlg 15) 3 3600 1440021600 1438207200 3613 (fromString "example.com.")
         (opaqueFromB64' "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj H5GaMWeG96GUVZu6ECKOQmemHDg==")

verifyExample :: Either String ()
verifyExample = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample
  rrsig  <- getRData "RRSIG"  rrsigExample
  verifyRRSIG dnskey rrsig rrExample
