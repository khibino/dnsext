{-# LANGUAGE OverloadedStrings #-}

module DNS.Iterative.RootTrustAnchors (
    rootSepDSs,
) where

import DNS.SEC
import qualified DNS.Types.Opaque as Opaque

{- import trust-anchor DS RData from
   https://data.iana.org/root-anchors/root-anchors.xml -}
rootSepDSs :: [RD_DS]
rootSepDSs =
    [ RD_DS 38696 RSASHA256 {- 8 -} SHA256 {- 2 -} digest2024
    , RD_DS 20326 RSASHA256 {- 8 -} SHA256 {- 2 -} digest2017
    ]
  where
    digest2024 =
        either (error . ("rootSepDSs: 2024: bad configuration: " ++)) id $
            Opaque.fromBase16
                "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
    digest2017 =
        either (error . ("rootSepDSs: 2017: bad configuration: " ++)) id $
            Opaque.fromBase16
                "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
