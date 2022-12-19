module DNS.Types.BaseEncoding (
    encodeBase16
  , decodeBase16
  , encodeBase32Hex
  , decodeBase32Hex
  , encodeBase64
  , decodeBase64
  ) where

import Data.ByteString (ByteString)

import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified DNS.Types.Base32Hex as B32H

encodeBase16 :: ByteString -> ByteString
encodeBase16 = B16.encode

decodeBase16 :: ByteString -> Either String ByteString
decodeBase16 = B16.decode

encodeBase32Hex :: ByteString -> ByteString
encodeBase32Hex = B32H.encode

decodeBase32Hex :: ByteString -> Either String ByteString
decodeBase32Hex = B32H.decode

encodeBase64 :: ByteString -> ByteString
encodeBase64 = B64.encode

decodeBase64 :: ByteString -> Either String ByteString
decodeBase64 = B64.decode
