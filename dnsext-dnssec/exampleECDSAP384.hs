
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

--    example.net. 3600 IN DNSKEY 257 3 14 (
--            xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
--            w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
--            /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )
dnskeyExample :: ResourceRecord
dnskeyExample = ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey' 257 3 14
         "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1 w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8 /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"

--    www.example.net. 3600 IN A 192.0.2.1
rrExample :: ResourceRecord
rrExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }

--    www.example.net. 3600 IN RRSIG A 14 3 3600 (
--            20100909102025 20100812102025 10771 example.net.
--            /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
--            95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
--            WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm )
rrsigExample :: ResourceRecord
rrsigExample = ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig A (toPubAlg 14) 3 3600 1284027625 1281608425 10771 (fromString "example.net.")
         (opaqueFromB64' "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP 95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm")

verifyExample :: Either String ()
verifyExample = do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyExample
  rrsig  <- getRData "RRSIG"  rrsigExample
  verifyRRSIG dnskey rrsig rrExample
