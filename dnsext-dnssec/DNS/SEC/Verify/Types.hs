{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.Types where

import qualified Data.ByteString as BS

-- dnsext-types
import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque

-- this package
import DNS.SEC.Imports
import DNS.SEC.Time
import DNS.SEC.PubAlg
import DNS.SEC.PubKey
import DNS.SEC.Types (RD_RRSIG(..), RD_DNSKEY(..), RD_DS(..))

keyTag :: RD_DNSKEY -> Word16
keyTag = keyTagFromBS . runSPut . putResourceData Canonical

-- KeyTag algorithm from https://datatracker.ietf.org/doc/html/rfc4034#appendix-B
keyTagFromBS :: ByteString -> Word16
keyTagFromBS bs = fromIntegral $ (sumK + sumK `shiftR` 16 .&. 0xFFFF) .&. 0xFFFF
  where
    addHigh w8 = (+ (fromIntegral w8 `shiftL` 8))
    addLow  w8 = (+  fromIntegral w8)
    loopOps = zipWith ($) (cycle [addHigh, addLow]) (BS.unpack bs)
    sumK :: Int
    sumK = foldr ($) 0 loopOps

data RRSIGImpl =
  forall pubkey sig .
  RRSIGImpl
  { rrsigIGetKey :: PubKey -> Either String pubkey
  , rrsigIGetSig :: Opaque -> Either String sig
  , rrsigIVerify :: pubkey -> sig -> ByteString -> Either String Bool
  }

putRRSIGHeader :: RD_RRSIG -> SPut ()
putRRSIGHeader RD_RRSIG{..} = do
    put16    $ fromTYPE rrsig_type
    putPubAlg  rrsig_pubalg
    put8       rrsig_num_labels
    putSeconds rrsig_ttl
    putDnsTime rrsig_expiration
    putDnsTime rrsig_inception
    put16      rrsig_key_tag
    putDomain Canonical rrsig_zone

verifyRRSIGwith :: RRSIGImpl -> RD_DNSKEY -> RD_RRSIG -> ResourceRecord -> Either String ()
verifyRRSIGwith RRSIGImpl{..} RD_DNSKEY{..} rrsig@RD_RRSIG{..} rr = do
  unless (dnskey_pubalg == rrsig_pubalg) $
    Left $ "verifyRRSIGwith: pubkey algorithm mismatch between DNSKEY and RRSIG: " ++ show dnskey_pubalg ++ " =/= " ++ show rrsig_pubalg
  {- TODO: check DNSKEY with keytag -}
  pubkey <- rrsigIGetKey dnskey_public_key
  sig    <- rrsigIGetSig rrsig_signature
  let str = runSPut (putRRSIGHeader rrsig >> putResourceRecord Canonical rr)
  good <- rrsigIVerify pubkey sig str
  unless good $ Left "verifyRRSIGwith: rejected on verification"

data DSImpl =
  forall digest .
  DSImpl
  { dsIGetDigest :: ByteString -> digest
  , dsIVerify :: digest -> ByteString -> Bool
  }

verifyDSwith :: DSImpl -> Domain -> RD_DNSKEY -> RD_DS -> Either String ()
verifyDSwith DSImpl{..} owner dnskey@RD_DNSKEY{..} RD_DS{..} = do
  unless (dnskey_pubalg == ds_pubalg) $
    Left $ "verifyDSwith: pubkey algorithm mismatch between DNSKEY and DS: " ++ show dnskey_pubalg ++ " =/= " ++ show ds_pubalg
  {- TODO: check DNSKEY with keytag -}
  let digest = dsIGetDigest $ runSPut $ putDomain Canonical owner >> putResourceData Canonical dnskey
      ds_digest' = Opaque.toByteString ds_digest
  unless (dsIVerify digest ds_digest') $
    Left "verifyDSwith: rejected on verification"
