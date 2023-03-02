{-# LANGUAGE OverloadedStrings #-}
{--# LANGUAGE RecordWildCards #-}

import Control.Monad (unless, filterM)
import Data.String (fromString)
import Data.List
import Data.Int
import Data.Word
import Data.ByteString (ByteString)
-- import Data.Time (UTCTime, parseTimeM, defaultTimeLocale)
-- import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)

import DNS.Types
import qualified DNS.Types.Opaque as Opaque

import DNS.SEC
import DNS.SEC.Verify

-----

type KeyTag_Case = (ResourceRecord, Word16)

caseKeyTag :: KeyTag_Case -> IO ()
caseKeyTag (dnskeyRR, tag) = either fail (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  unless (keyTag dnskey == tag) $
    Left $ "caseKeyTag: keytag does not match: " ++ show (keyTag dnskey) ++ " =/= " ++ show tag
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-----

type DS_CASE = (ResourceRecord, ResourceRecord)

caseDS :: DS_CASE -> IO ()
caseDS (dnskeyRR, dsRR) = either fail (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  ds     <- takeRData "DS"     dsRR
  verifyDS (rrname dnskeyRR) dnskey ds
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-----

type RRSIG_CASE = (ResourceRecord, [ResourceRecord], ResourceRecord)

caseRRSIG :: RRSIG_CASE -> Either String ()
caseRRSIG (dnskeyRR, targets, rrsigRR) = do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  rrsig  <- takeRData "RRSIG"  rrsigRR
  verifyRRSIG dnskey rrsig targets
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

{-
caseRRSIG' :: RRSIG_CASE -> Either String ()
caseRRSIG' (dnskeyRR, targets, rrsigRR) = do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  rrsig  <- takeRData "RRSIG"  rrsigRR
  verifyRRSIG' dnskey rrsig targets
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
 -}

---

-- com.			86400	IN	RRSIG	DNSKEY 8 1 86400 20230316182421 20230301181921 30909 com. IgYGztbEeTK3gNyjclRD8rtl4RttqWo0TxSAE4X/h/VVzKwRBFvx35yn O1YDoZc8DS8LoEsAuKEpiwa+bYO3u39BcTXDReKw+F+N4RlwBYSanjP9 ye8DLZb2zOUsXdZp1Lv5RXApV1JdOel7oMLY9MQE7etaREAlDzDPGOET 022SRU+NpXgB8x0yg7fbfDpTRRL1OXijmfbpSS6VNC8nqjQp5ZOLdTyM qidx4WTaJ7ZRLhKWO31yaw4F3cpg4ZM+4finK0v3GnESLCvDDti6cFYK ooVkkgIWQVinrcwQKe8S6AEJzUd+lsqsOuzhojPa8JSTwbnz2sp/iGRO MxbmrQ==
-- com.	86400(1 day)	IN	RRSIG	RD_RRSIG {rrsig_type = DNSKEY, rrsig_pubalg = RSASHA256, rrsig_num_labels = 1, rrsig_ttl = 86400(1 day), rrsig_expiration = 1678991061, rrsig_inception = 1677694761, rrsig_key_tag = 30909, rrsig_zone = "com.", rrsig_signature = \# 256 220606ced6c47932b780dca3725443f2bb65e11b6da96a344f14801385ff87f555ccac11045bf1df9ca73b5603a1973c0d2f0ba04b00b8a1298b06be6d83b7bb7f417135c345e2b0f85f8de1197005849a9e33fdc9ef032d96f6cce52c5dd669d4bbf945702957525d39e97ba0c2d8f4c404edeb5a4440250f30cf18e113d36d92454f8da57801f31d3283b7db7c3a534512f53978a399f6e9492e95342f27aa3429e5938b753c8caa2771e164da27b6512e12963b7d726b0e05ddca60e1933ee1f8a72b4bf71a71122c2bc30ed8ba70560aa285649202164158a7adcc1029ef12e80109cd477e96caac3aece1a233daf09493c1b9f3daca7f88644e3316e6ad}
com_dnskey_rrsig_30909 :: RRSIG_CASE
com_dnskey_rrsig_30909 =
  ( com_dnskey_2
  , [com_dnskey_1, com_dnskey_2]
  , ResourceRecord { rrname = "com.", rrttl = 86400, rrclass = classIN, rrtype = RRSIG, rdata = sigrd }
  )
  where sigrd = rd_rrsig' DNSKEY 8 1 86400 1678991061 1677694761 30909 "com."
                "IgYGztbEeTK3gNyjclRD8rtl4RttqWo0TxSAE4X/h/VVzKwRBFvx35yn O1YDoZc8DS8LoEsAuKEpiwa+bYO3u39BcTXDReKw+F+N4RlwBYSanjP9 ye8DLZb2zOUsXdZp1Lv5RXApV1JdOel7oMLY9MQE7etaREAlDzDPGOET 022SRU+NpXgB8x0yg7fbfDpTRRL1OXijmfbpSS6VNC8nqjQp5ZOLdTyM qidx4WTaJ7ZRLhKWO31yaw4F3cpg4ZM+4finK0v3GnESLCvDDti6cFYK ooVkkgIWQVinrcwQKe8S6AEJzUd+lsqsOuzhojPa8JSTwbnz2sp/iGRO MxbmrQ=="

com_dnskey_1, com_dnskey_2 :: ResourceRecord

-- com.			86400	IN	DNSKEY	256 3 8 AwEAAb+cCgnkrABgFJ67lulzA/rJtcnjALB/gP3Q33PdpNl3VoW/V0GW zo99F7I7FyK/lpRTgoPp2pe2DRtoocL9XhqVoEDDV04KPk6kJXacSplt f9xu/j+sJElOGz/cWzAxIN2sTJxsRyNRwenTLJLd1pLDqB80hB25he9/ d2bwmuWhC7l7mHrXr0RgvkxGGSeP/k0MQg7JGzl1mC+P/yqwx6E=
-- (key_tag: 36739)
com_dnskey_1 = ResourceRecord { rrname = "com.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where rd = rd_dnskey' 256 3 8
             "AwEAAb+cCgnkrABgFJ67lulzA/rJtcnjALB/gP3Q33PdpNl3VoW/V0GW zo99F7I7FyK/lpRTgoPp2pe2DRtoocL9XhqVoEDDV04KPk6kJXacSplt f9xu/j+sJElOGz/cWzAxIN2sTJxsRyNRwenTLJLd1pLDqB80hB25he9/ d2bwmuWhC7l7mHrXr0RgvkxGGSeP/k0MQg7JGzl1mC+P/yqwx6E="

-- com.			86400	IN	DNSKEY	257 3 8 AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVcNcsIszxNFxsB fKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK8k7evWEm u/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPN IwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0H XvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh 2K/BgUe8Hs0XVcdPKrtyYnoQHd2ynKPcMMlTEih2/2HDHjRPJ2aywIpK Nnv4oPo/
-- (key_tag: 30909)
com_dnskey_2 = ResourceRecord { rrname = "com.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where rd = rd_dnskey' 257 3 8
             "AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVcNcsIszxNFxsB fKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK8k7evWEm u/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPN IwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0H XvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh 2K/BgUe8Hs0XVcdPKrtyYnoQHd2ynKPcMMlTEih2/2HDHjRPJ2aywIpK Nnv4oPo/"

---

-- cloudflare.com.		3600	IN	RRSIG	DNSKEY 13 2 3600 20230408195305 20230206195305 2371 cloudflare.com. yGqSwmyDNu/GSb3mx2bwUiyPhYfZhKO9ORqKULfjNFEXmdzHU4NSddkO Ym8gCcQ3fgnEJU+GZ1/b9xdnFrPyxA==
-- cloudflare.com.	3600(1 hour)	IN	RRSIG	RD_RRSIG {rrsig_type = DNSKEY, rrsig_pubalg = ECDSAP256SHA256, rrsig_num_labels = 2, rrsig_ttl = 3600(1 hour), rrsig_expiration = 1680983585, rrsig_inception = 1675713185, rrsig_key_tag = 2371, rrsig_zone = "cloudflare.com.", rrsig_signature = \# 64 c86a92c26c8336efc649bde6c766f0522c8f8587d984a3bd391a8a50b7e334511799dcc753835275d90e626f2009c4377e09c4254f86675fdbf7176716b3f2c4}
cloudflare_dnskey_rrsig_2371 :: RRSIG_CASE
cloudflare_dnskey_rrsig_2371 =
  ( cloudflare_dnskey_1
  , [cloudflare_dnskey_1, cloudflare_dnskey_2]
  , ResourceRecord { rrname = "cloudflare.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sigrd }
  )
  where sigrd = rd_rrsig' DNSKEY 13 2 3600 1680983585 1675713185 2371 "cloudflare.com."
                "yGqSwmyDNu/GSb3mx2bwUiyPhYfZhKO9ORqKULfjNFEXmdzHU4NSddkO Ym8gCcQ3fgnEJU+GZ1/b9xdnFrPyxA=="

cloudflare_dnskey_1, cloudflare_dnskey_2 :: ResourceRecord

-- cloudflare.com.		3600	IN	DNSKEY	257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+ KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
-- (key_tag: 2371)
cloudflare_dnskey_1 = ResourceRecord { rrname = "cloudflare.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where rd = rd_dnskey' 257 3 13
             "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+ KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="

-- cloudflare.com.		3600	IN	DNSKEY	256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8 KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==
-- (key_tag: 34505)
cloudflare_dnskey_2 = ResourceRecord { rrname = "cloudflare.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where rd = rd_dnskey' 256 3 13
             "oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8 KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="

---

-- iij.ad.jp.		86400	IN	RRSIG	DNSKEY 8 3 86400 20230331151005 20230301151005 2508 iij.ad.jp. fyyIJcl8gAGIccYSNMJWvzEeRSQikG2aDx1RwDnQEPJG26H2LcbwJaSI 88cqIQcpLxHOrrWUyBqPNKkZjrq038fWw0ZT8trgvajHZ1bkiqOGIsc2 71QhjLXA+BOChnf78+kw6aFS5wi8A5EE/PBPMPYCCC1Z8uPHZKPvtjYP Ux0=
-- iij.ad.jp.	86400(1 day)	IN	RRSIG	RD_RRSIG {rrsig_type = DNSKEY, rrsig_pubalg = RSASHA256, rrsig_num_labels = 3, rrsig_ttl = 86400(1 day), rrsig_expiration = 1680275405, rrsig_inception = 1677683405, rrsig_key_tag = 2508, rrsig_zone = "iij.ad.jp.", rrsig_signature = \# 128 7f2c8825c97c80018871c61234c256bf311e452422906d9a0f1d51c039d010f246dba1f62dc6f025a488f3c72a2107292f11ceaeb594c81a8f34a9198ebab4dfc7d6c34653f2dae0bda8c76756e48aa38622c736ef54218cb5c0f813828677fbf3e930e9a152e708bc039104fcf04f30f602082d59f2e3c764a3efb6360f531d}
iij_dnskey_rrsig_2508 :: RRSIG_CASE
iij_dnskey_rrsig_2508 =
  ( iij_dnskey_1
  , [iij_dnskey_1, iij_dnskey_2, iij_dnskey_sep]
  , ResourceRecord { rrname = "iij.ad.jp.", rrttl = 86400, rrclass = classIN, rrtype = RRSIG, rdata = sigrd }
  )
  where sigrd = rd_rrsig' DNSKEY 8 3 86400 1680275405 1677683405 2508 "iij.ad.jp."
                "fyyIJcl8gAGIccYSNMJWvzEeRSQikG2aDx1RwDnQEPJG26H2LcbwJaSI 88cqIQcpLxHOrrWUyBqPNKkZjrq038fWw0ZT8trgvajHZ1bkiqOGIsc2 71QhjLXA+BOChnf78+kw6aFS5wi8A5EE/PBPMPYCCC1Z8uPHZKPvtjYP Ux0="

-- iij.ad.jp.		86400	IN	RRSIG	DNSKEY 8 3 86400 20230331151005 20230301151005 10855 iij.ad.jp. mkJ5rKpO3LgiD4um9fPZ5D3fi0kdsUfOPrKIhmR6Nz0rBhYuJ/mlgCc9 th/tMRvmB8kp7huCcEhKYRcaG7Oyme3HhKJMSLkpetrcPqQcnHDYJ2Nc BhBlJovfyXB0BvM3NHFIjLlNu9R5hiMyEvJV+gv2B3m0HBxrA/FedXEU Vjez3Q4xhDYlJg9eyOe0vdCF92zGvtGPZD1QTwyqF+3cBnw0olZiFYwo cMDEKLsyMWVOzjJ626U9+ow5jQqI83Vrt8NwWrB7vD9jwfGmjyC4Gjuz nRvpwAWgwG5VK7KMTyzL0gKUAqGCCRSMOzA5RPmDIvfP1rui/CbsO+FX OcRnLg==
-- iij.ad.jp.	86400(1 day)	IN	RRSIG	RD_RRSIG {rrsig_type = DNSKEY, rrsig_pubalg = RSASHA256, rrsig_num_labels = 3, rrsig_ttl = 86400(1 day), rrsig_expiration = 1680275405, rrsig_inception = 1677683405, rrsig_key_tag = 10855, rrsig_zone = "iij.ad.jp.", rrsig_signature = \# 256 9a4279acaa4edcb8220f8ba6f5f3d9e43ddf8b491db147ce3eb28886647a373d2b06162e27f9a580273db61fed311be607c929ee1b8270484a61171a1bb3b299edc784a24c48b9297adadc3ea41c9c70d827635c061065268bdfc9707406f3373471488cb94dbbd47986233212f255fa0bf60779b41c1c6b03f15e7571145637b3dd0e31843625260f5ec8e7b4bdd085f76cc6bed18f643d504f0caa17eddc067c34a25662158c2870c0c428bb3231654ece327adba53dfa8c398d0a88f3756bb7c3705ab07bbc3f63c1f1a68f20b81a3bb39d1be9c005a0c06e552bb28c4f2ccbd2029402a18209148c3b303944f98322f7cfd6bba2fc26ec3be15739c4672e}
iij_dnskey_rrsig_10855 :: RRSIG_CASE
iij_dnskey_rrsig_10855 =
  ( iij_dnskey_sep
  , [iij_dnskey_1, iij_dnskey_2, iij_dnskey_sep]
  , ResourceRecord { rrname = "iij.ad.jp.", rrttl = 86400, rrclass = classIN, rrtype = RRSIG, rdata = sigrd }
  )
  where sigrd = rd_rrsig' DNSKEY 8 3 86400 1680275405 1677683405 10855 "iij.ad.jp."
                "mkJ5rKpO3LgiD4um9fPZ5D3fi0kdsUfOPrKIhmR6Nz0rBhYuJ/mlgCc9 th/tMRvmB8kp7huCcEhKYRcaG7Oyme3HhKJMSLkpetrcPqQcnHDYJ2Nc BhBlJovfyXB0BvM3NHFIjLlNu9R5hiMyEvJV+gv2B3m0HBxrA/FedXEU Vjez3Q4xhDYlJg9eyOe0vdCF92zGvtGPZD1QTwyqF+3cBnw0olZiFYwo cMDEKLsyMWVOzjJ626U9+ow5jQqI83Vrt8NwWrB7vD9jwfGmjyC4Gjuz nRvpwAWgwG5VK7KMTyzL0gKUAqGCCRSMOzA5RPmDIvfP1rui/CbsO+FX OcRnLg=="

iij_dnskey_1, iij_dnskey_2, iij_dnskey_sep :: ResourceRecord

-- iij.ad.jp.		86400	IN	DNSKEY	256 3 8 AwEAAdyl8rJAwIXpgJn4HKW9mIhlJQHjLkq91UL+qcfiFkMmQoIxCuDc RBKgSfdgSavRThrttFGn6qFHSYDr2NmbiDkQwmSksnH13UTUK+hbPUev LOa76MchHxvA+GNkulUcHEFdp+ic2QAvGnahrzz9iMCTsA7y3UOHJS9V sxFwoPhX
-- key_tag: 2508
iij_dnskey_1 = ResourceRecord { rrname = "iij.ad.jp.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where rd = rd_dnskey' 256 3 8
             " AwEAAdyl8rJAwIXpgJn4HKW9mIhlJQHjLkq91UL+qcfiFkMmQoIxCuDc \
             \ RBKgSfdgSavRThrttFGn6qFHSYDr2NmbiDkQwmSksnH13UTUK+hbPUev \
             \ LOa76MchHxvA+GNkulUcHEFdp+ic2QAvGnahrzz9iMCTsA7y3UOHJS9V \
             \ sxFwoPhX "

-- iij.ad.jp.		86400	IN	DNSKEY	257 3 8 AwEAAd5lYXd3r4sru3TmsRNnQn7vG3R6HbGx1LSXOktO1GBbbTpUh0s5 lI6dBqbaL+NiaQ9nvI9r9InOXOIxW6UvU2Mvx0N0KRkeZvk4e4xmZx2I WxA7Nx+lQJyEjmGRdfNHgjAww99fycolKvm1fTunWwKtoqR6KsiiFDQW 8x1yYWJJhqGV0G2PTyQBUBLfyEaG15+a9jGAC907GOs5W3zHGKU0xbza q5BoddvHoNoUqKDnbCBG8qWunm/tXxSSelrlWLA5nDB19NQrxuGzCIpw 44WrqWANTFGmPQ61e+qr6RfBOGHgUFPsiYOi87vu/lKy2zZYB/W32A4P 2Sp3e8mzwfk=
-- key_tag: 10855
iij_dnskey_sep = ResourceRecord { rrname = "iij.ad.jp.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where rd = rd_dnskey' 257 3 8
             " AwEAAd5lYXd3r4sru3TmsRNnQn7vG3R6HbGx1LSXOktO1GBbbTpUh0s5 \
             \ lI6dBqbaL+NiaQ9nvI9r9InOXOIxW6UvU2Mvx0N0KRkeZvk4e4xmZx2I \
             \ WxA7Nx+lQJyEjmGRdfNHgjAww99fycolKvm1fTunWwKtoqR6KsiiFDQW \
             \ 8x1yYWJJhqGV0G2PTyQBUBLfyEaG15+a9jGAC907GOs5W3zHGKU0xbza \
             \ q5BoddvHoNoUqKDnbCBG8qWunm/tXxSSelrlWLA5nDB19NQrxuGzCIpw \
             \ 44WrqWANTFGmPQ61e+qr6RfBOGHgUFPsiYOi87vu/lKy2zZYB/W32A4P \
             \ 2Sp3e8mzwfk= "

-- iij.ad.jp.		86400	IN	DNSKEY	256 3 8 AwEAAcuOTJ2YgjQNvVVmuT8kRDxihkqPzNDbrf9ThZ7kio5RIIfzsIFj LQTxP1gLqQ0zHZua2GPd99Z67ZejF5JWkqXkS18kBNBf8xXJcpLHOvmA UxI4hNkxsiH/iyQnZjMxSNjkMkJGWzwkN2BosGv3vA7/Sb1oXQ93Sjmj bWlnZ8Dz
-- key_tag: 8289
iij_dnskey_2 = ResourceRecord { rrname = "iij.ad.jp.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = rd }
  where rd = rd_dnskey' 256 3 8
             " AwEAAcuOTJ2YgjQNvVVmuT8kRDxihkqPzNDbrf9ThZ7kio5RIIfzsIFj \
             \ LQTxP1gLqQ0zHZua2GPd99Z67ZejF5JWkqXkS18kBNBf8xXJcpLHOvmA \
             \ UxI4hNkxsiH/iyQnZjMxSNjkMkJGWzwkN2BosGv3vA7/Sb1oXQ93Sjmj \
             \ bWlnZ8Dz "

-----
-- helpers

keyTag' :: ResourceRecord -> Maybe Word16
keyTag' = fmap keyTag . fromRData . rdata

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
  either (error "opaqueFromB16Hex: fail to decode hex") id .
  Opaque.fromBase16 . (fromString :: String -> ByteString) . filter (/= ' ')

opaqueFromB32Hex :: String -> Opaque
opaqueFromB32Hex =
  either (error "opaqueFromB32Hex: fail to decode base32hex") id .
  Opaque.fromBase32Hex . (fromString :: String -> ByteString) . filter (/= ' ')

opaqueFromB64 :: String -> Opaque
opaqueFromB64 =
  either (error "opaqueFromB64: fail to decode base64") id .
  Opaque.fromBase64 . (fromString :: String -> ByteString) . filter (/= ' ')

---

-- parseRRSIGTime :: String -> Maybe UTCTime
-- parseRRSIGTime s = parseTimeM False defaultTimeLocale "%Y%m%d%H%M%S%Z" (s ++ "UTC")

-- getRRSIGTimeInt :: String -> Maybe Int64
-- getRRSIGTimeInt s = floor . utcTimeToPOSIXSeconds <$> parseRRSIGTime s

-- getRRSIGTimeInt' :: String -> Int64
-- getRRSIGTimeInt' s = maybe (error $ "getRRSIGTimeInt': fail to parse: " ++ s) id $ getRRSIGTimeInt s
