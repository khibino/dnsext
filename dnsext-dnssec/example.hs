
import Data.String (fromString)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B8

-- memory
import Data.ByteArray.Encoding (Base (Base64), convertFromBase)

import DNS.Types
import DNS.SEC


bytesFromB64' :: ByteString -> ByteString
bytesFromB64' = either (error "bytesFromB64': fail to decode base64") id . bytesFromB64

bytesFromB64 :: ByteString -> Either String ByteString
bytesFromB64 = convertFromBase Base64 . B8.filter (/= ' ')

dnskeyZskIIJ2 :: ResourceRecord
dnskeyZskIIJ2 = ResourceRecord { rrname = fromString "iij.ad.jp.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where
    rd = rd_dnskey 256 3 8
         (byteStringToOpaque $ bytesFromB64' $
          fromString "AwEAAeD+V7UXu0mzGaIRtZryR7qz/+evt1GX+pZJVgcVC9n67c8dzrv3 YrIuNUlRVKTOKcTOuwA6/I3oo5P/j+zTKzusqa9MyJuIXFzROsJ2kjCV KFVxB+L+rfQxhO+334fmFFehPouDew2kAPP6YKDufkkMwSfj/VUooXoN rqr42o97")

rrsigEngBlog :: ResourceRecord
rrsigEngBlog = ResourceRecord { rrname = fromString "eng-blog.iij.ad.jp.", rrttl = 300, rrclass = classIN, rrtype = RRSIG, rdata = rd }
  where
    rd = rd_rrsig A 8 4 300
         1667401805
         1664809805
         34908
         (fromString "iij.ad.jp.")
         (byteStringToOpaque $ bytesFromB64' $
          fromString "QEv8fD6+zGWJxVRwXN/4OQP/fJWjb8+zeKugVYdvGClgrFssNUTcx8SU yoPbRrW+xqZePxp7i1yGfBapZVq94mCR/x9W88gT5zl0pZ+pAAbfmg9a WD+/UU+27MgJxZFdHXIxBHSvoDHxsA4RihACCT9drk+Sueg2MbbwU38d dGM=")

engBlogA :: ResourceRecord
engBlogA = ResourceRecord { rrname = fromString "eng-blog.iij.ad.jp.", rrttl = 300, rrclass = classIN, rrtype = A, rdata = rd_a $ read "202.232.2.183" }

verifyRRSIGEngBlog :: Either String ByteString
verifyRRSIGEngBlog = do
  let x = rdata dnskeyZskIIJ2
  dnskey <- maybe (Left $ "not DNSKEY: " ++ show x) Right $ fromRData x
  let y = rdata rrsigEngBlog
  rrsig  <- maybe (Left $ "not RRSIG: "  ++ show y) Right $ fromRData y
  verifyRRSIG dnskey rrsig engBlogA
