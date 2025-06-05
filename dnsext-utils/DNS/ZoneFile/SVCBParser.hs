
module DNS.ZoneFile.SVCBParser where

-- GHC
import Control.Applicative
import Control.Monad
import Data.Char (chr, toLower)
import Data.List
import Data.Word (Word8)
import qualified Data.ByteString.Short as Short
import qualified Data.Word8 as W8
import Text.Read (readMaybe)

-- dnsext-*
import qualified DNS.Types.Opaque as Opaque
import DNS.SVCB
import DNS.SVCB.Internal

-- this package
import DNS.Parser

type SBS = Short.ShortByteString

w8chr :: Word8 -> Char
w8chr = chr . fromIntegral

sbsString :: SBS -> String
sbsString s = [ w8chr w | w <- Short.unpack s ]

---

svcParam :: MonadParser t s m => SBS -> m (SvcParamKey, SvcParamValue)
svcParam s = do
    (k', getV) <- svcParamKey k
    v' <- maybe invalid pure $ getV v
    pure (k', v')
  where
    (k, v) = Short.break (== W8._equal) s
    invalid = parseError $ "ZoneFile: SvcParamValue: invalid value pattern: " ++ sbsString v

svcParamKey :: MonadParser t s m => SBS -> m (SvcParamKey, SBS -> Maybe SvcParamValue)
svcParamKey s = maybe unknown pure $ getSvcParamKey s
  where
    unknown = parseError $ "ZoneFile: SvcParamKey: unknown key name: " ++ sbsString s

{- FOURMOLU_DISABLE -}
getSvcParamKey :: SBS -> Maybe (SvcParamKey, SBS -> Maybe SvcParamValue)
getSvcParamKey s = lookup lc knownSvcParamKeys <|> keyNNNNN
  where
    lc = [ toLower (w8chr w) | w <- Short.unpack s ]
    keyNNNNN = do
        sn <- stripPrefix "key" lc
        -- https://datatracker.ietf.org/doc/html/rfc9460#section-2.1
        -- 'the unknown-key presentation format "keyNNNNN" where NNNNN is the numeric value of the key type without leading zeros.'
        guard (take 1 sn /= "0")
        k <- readMaybe sn
        Just (toSvcParamKey k, valueOpaque)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- | SvcParamKey data table:
--   https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
knownSvcParamKeys :: [(String, (SvcParamKey, SBS -> Maybe SvcParamValue))]
knownSvcParamKeys =
    [ ("mandatory"             , (SPK_Mandatory          , valueMandatory     ))
    , ("alpn"                  , (SPK_ALPN               , undefined          ))
    , ("no-default-alpn"       , (SPK_NoDefaultALPN      , undefined          ))
    , ("port"                  , (SPK_Port               , undefined          ))
    , ("ipv4hint"              , (SPK_IPv4Hint           , undefined          ))
    , ("ech"                   , (SPK_ECH                , undefined          ))
    , ("ipv6hint"              , (SPK_IPv6Hint           , undefined          ))
    , ("dohpath"               , (SPK_DoHPath            , undefined          ))
    , ("ohttp"                 , (SPK_OHTTP              , undefined          ))
    , ("tls-supported-groups"  , (SPK_TLSSupporedGroups  , undefined          ))
    ]
{- FOURMOLU_ENABLE -}

---

valueMandatory :: SBS -> Maybe SvcParamValue
valueMandatory v = toSvcParamValue . SPV_Mandatory <$> mapM (fmap fst . getSvcParamKey) (Short.split W8._comma v)

valueOpaque :: SBS -> Maybe SvcParamValue
valueOpaque v = Just (toSvcParamValue $ SPV_Opaque $ Opaque.fromShortByteString v)
