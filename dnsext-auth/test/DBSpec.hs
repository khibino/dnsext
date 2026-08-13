{-# LANGUAGE OverloadedStrings #-}

module DBSpec where

import Test.Hspec

import DNS.Auth.DB
import DNS.SEC
import DNS.Types

spec :: Spec
spec = describe "creating DB" $ do
    runIO $ runInitIO $ addResourceDataForDNSSEC
    let zone = "example.jp."
    it "detect CNAME with other RRs" $ do
        loadDB zone "test/cname.zone" `shouldThrow` authError
    it "detect multiple CNAMEs" $ do
        loadDB zone "test/cname2.zone" `shouldThrow` authError

authError :: AuthException -> Bool
authError _ = True
