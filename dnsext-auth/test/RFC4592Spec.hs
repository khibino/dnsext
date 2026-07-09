{-# LANGUAGE OverloadedStrings #-}

module RFC4592Spec where

import Test.Hspec

import DNS.Auth.Algorithm
import DNS.Auth.DB
import DNS.SEC
import DNS.SEC.Verify
import DNS.Types

import Data.Maybe

spec :: Spec
spec = describe "authoritative algorithm" $ do
    runIO $ runInitIO $ addResourceDataForDNSSEC
    let zone = "example."
    edb <- runIO $ do
        rrs <- loadZoneFile zone "test/rfc4592.zone"
        (_pub, _pri, dnskey, _ds, doSign) <-
            prepareDNSSEC $
                DNSSECinfo
                    { dnssecInfoZone = zone
                    , dnssecInfoPubAlg = ED25519
                    , dnssecInfoDigestAlg = SHA256
                    , dnssecInfoTTL = 3600
                    , dnssecInfoDuration = 86400
                    }
        makeDBforPrimary zone doSign (rrs ++ [dnskey])
    let db = fromJust edb
    doit db
    db2 <- fromJust <$> runIO (makeDBforSecondary zone $ dbAll db)
    doit db2

doit :: DB -> Spec
doit db = do
    it "implements Sec 2.2.1" $ do
        let query = defaultQuery{question = Question "host3.example." MX IN}
            ans = getAnswer db query
        rcode ans `shouldBe` NoErr
        length (answer ans) `shouldBe` 1
        answer ans `shouldSatisfy` include "host3.example." MX

includeRRSIG :: Domain -> TYPE -> [ResourceRecord] -> Bool
includeRRSIG dom typ rs = any has rs
  where
    has r =
        rrname r == dom && rrtype r == RRSIG && case fromRData $ rdata r of
            Nothing -> False
            Just rd -> rrsig_type rd == typ

includeNS :: Domain -> [ResourceRecord] -> Bool
includeNS dom rs = any has rs
  where
    has r = case fromRData $ rdata r of
        Nothing -> False
        Just rd -> ns_domain rd == dom

include :: Domain -> TYPE -> [ResourceRecord] -> Bool
include dom typ rs = any has rs
  where
    has r = rrname r == dom && rrtype r == typ

dnssecQuery :: DNSMessage
dnssecQuery =
    defaultQuery
        { ednsHeader = EDNSheader defaultEDNS{ednsDnssecOk = True}
        }
