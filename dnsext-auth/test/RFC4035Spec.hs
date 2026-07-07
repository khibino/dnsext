{-# LANGUAGE OverloadedStrings #-}

module RFC4035Spec where

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
        rrs <- loadZoneFile zone "test/rfc4035.zone"
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

-- Canonical order:
-- example.jp.
-- b.example.jp.
-- a.ent2.ent1.example.jp.
-- exist.example.jp.
-- exist-cname.example.jp.
-- ext-cname.example.jp.
-- fault-cname.example.jp.
-- in2.example.jp.
-- ns.example.jp.
-- sibling2.example.jp.

doit :: DB -> Spec
doit db = do
    it "passes the test in Appendix B.1" $ do
        let query = dnssecQuery{question = Question "x.w.example." MX IN}
            ans = getAnswer db query
        rcode ans `shouldBe` NoErr
        length (answer ans) `shouldBe` 2
        answer ans `shouldSatisfy` include "x.w.example." MX
        answer ans `shouldSatisfy` includeRRSIG "x.w.example." MX
        length (authority ans) `shouldBe` 0
        -- fixme
        length (additional ans) `shouldBe` 0
        -- fixme: xxx resolving MX
        flags ans `shouldSatisfy` authAnswer
    it "passes the test in Appendix B.2" $ do
        let query = dnssecQuery{question = Question "ml.example." A IN}
            ans = getAnswer db query
        rcode ans `shouldBe` NXDomain
        length (answer ans) `shouldBe` 0
        length (authority ans) `shouldBe` 4 -- fixme
        authority ans `shouldSatisfy` include "example." SOA
        authority ans `shouldSatisfy` includeRRSIG "example." SOA
        authority ans `shouldSatisfy` include "b.example." NSEC
        authority ans `shouldSatisfy` includeRRSIG "b.example." NSEC
        -- fixme
        -- authority ans `shouldSatisfy` include "example." NSEC
        -- fixme
        -- authority ans `shouldSatisfy` includeRRSIG "example." NSEC
        length (additional ans) `shouldBe` 0
        flags ans `shouldSatisfy` authAnswer
    it "passes the test in Appendix B.3" $ do
        let query = dnssecQuery{question = Question "ns1.example." MX IN}
            ans = getAnswer db query
        rcode ans `shouldBe` NoErr
        length (answer ans) `shouldBe` 0
        length (authority ans) `shouldBe` 4
        authority ans `shouldSatisfy` include "example." SOA
        authority ans `shouldSatisfy` includeRRSIG "example." SOA
        authority ans `shouldSatisfy` include "ns1.example." NSEC
        authority ans `shouldSatisfy` includeRRSIG "ns1.example." NSEC
        length (additional ans) `shouldBe` 0
        flags ans `shouldSatisfy` authAnswer
    it "passes the test in Appendix B.4" $ do
        let query = dnssecQuery{question = Question "mc.a.example." MX IN}
            ans = getAnswer db query
        rcode ans `shouldBe` NoErr
        length (answer ans) `shouldBe` 0
        length (authority ans) `shouldBe` 4
        authority ans `shouldSatisfy` includeNS "ns1.a.example."
        authority ans `shouldSatisfy` includeNS "ns2.a.example."
        authority ans `shouldSatisfy` include "a.example." DS
        authority ans `shouldSatisfy` includeRRSIG "a.example." DS
        length (additional ans) `shouldBe` 2
        additional ans `shouldSatisfy` include "ns1.a.example." A
        additional ans `shouldSatisfy` include "ns2.a.example." A
        flags ans `shouldSatisfy` not . authAnswer
    it "passes the test in Appendix B.5" $ do
        let query = dnssecQuery{question = Question "mc.b.example." MX IN}
            ans = getAnswer db query
        rcode ans `shouldBe` NoErr
        length (answer ans) `shouldBe` 0
        length (authority ans) `shouldBe` 4
        authority ans `shouldSatisfy` includeNS "ns1.b.example."
        authority ans `shouldSatisfy` includeNS "ns2.b.example."
        authority ans `shouldSatisfy` include "b.example." NSEC
        authority ans `shouldSatisfy` includeRRSIG "b.example." NSEC
        length (additional ans) `shouldBe` 2
        additional ans `shouldSatisfy` include "ns1.b.example." A
        additional ans `shouldSatisfy` include "ns2.b.example." A
        flags ans `shouldSatisfy` not . authAnswer

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
