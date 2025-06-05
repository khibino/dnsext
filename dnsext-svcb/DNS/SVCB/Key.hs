{-# LANGUAGE PatternSynonyms #-}

module DNS.SVCB.Key where

import DNS.SVCB.Imports

newtype SvcParamKey = SvcParamKey
    { fromSvcParamKey :: Word16
    }
    deriving (Eq, Ord)

{- FOURMOLU_DISABLE -}
instance Show SvcParamKey where
    show SPK_Mandatory          = "mandatory"
    show SPK_ALPN               = "alpn"
    show SPK_NoDefaultALPN      = "no-default-alpn"
    show SPK_Port               = "port"
    show SPK_IPv4Hint           = "ipv4hint"
    show SPK_ECH                = "ech"
    show SPK_IPv6Hint           = "ipv6hint"
    show SPK_DoHPath            = "dohpath"
    show SPK_OHTTP              = "ohttp"
    show SPK_TLSSupporedGroups  = "tls-supported-groups"
    show (SvcParamKey n)        = "SvcParamKey" ++ show n -- no space
{- FOURMOLU_ENABLE -}

toSvcParamKey :: Word16 -> SvcParamKey
toSvcParamKey = SvcParamKey

-- SvcParamKey data table:
-- https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml

pattern SPK_Mandatory :: SvcParamKey
pattern SPK_Mandatory = SvcParamKey 0

pattern SPK_ALPN :: SvcParamKey
pattern SPK_ALPN = SvcParamKey 1

pattern SPK_NoDefaultALPN :: SvcParamKey
pattern SPK_NoDefaultALPN = SvcParamKey 2

pattern SPK_Port :: SvcParamKey
pattern SPK_Port = SvcParamKey 3

pattern SPK_IPv4Hint :: SvcParamKey
pattern SPK_IPv4Hint = SvcParamKey 4

pattern SPK_ECH :: SvcParamKey
pattern SPK_ECH = SvcParamKey 5

pattern SPK_IPv6Hint :: SvcParamKey
pattern SPK_IPv6Hint = SvcParamKey 6

pattern SPK_DoHPath :: SvcParamKey
pattern SPK_DoHPath = SvcParamKey 7

pattern SPK_OHTTP :: SvcParamKey
pattern SPK_OHTTP = SvcParamKey 8

pattern SPK_TLSSupporedGroups :: SvcParamKey
pattern SPK_TLSSupporedGroups = SvcParamKey 9
