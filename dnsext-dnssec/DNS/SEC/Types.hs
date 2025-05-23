{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Types where

import DNS.SEC.Flags
import DNS.SEC.HashAlg
import DNS.SEC.Imports
import DNS.SEC.PubAlg
import DNS.SEC.PubKey
import DNS.SEC.Time
import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque

import Data.Array
import Data.Array.ST

pattern DS :: TYPE
pattern DS = TYPE 43 -- RFC 4034

-- | RRSIG (RFC4034)
pattern RRSIG :: TYPE
pattern RRSIG = TYPE 46 -- RFC 4034

-- | NSEC (RFC4034)
pattern NSEC :: TYPE
pattern NSEC = TYPE 47 -- RFC 4034

-- | DNSKEY (RFC4034)
pattern DNSKEY :: TYPE
pattern DNSKEY = TYPE 48 -- RFC 4034

-- | NSEC3 (RFC5155)
pattern NSEC3 :: TYPE
pattern NSEC3 = TYPE 50 -- RFC 5155

-- | NSEC3PARAM (RFC5155)
pattern NSEC3PARAM :: TYPE
pattern NSEC3PARAM = TYPE 51 -- RFC 5155

-- | Child DS (RFC7344)
pattern CDS :: TYPE
pattern CDS = TYPE 59 -- RFC 7344

-- | DNSKEY(s) the Child wants reflected in DS (RFC7344)
pattern CDNSKEY :: TYPE
pattern CDNSKEY = TYPE 60 -- RFC 7344

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | DNSSEC signature
--
-- As noted in
-- <https://tools.ietf.org/html/rfc4034#section-3.1.5 Section 3.1.5 of RFC 4034>
-- the RRsig inception and expiration times use serial number arithmetic.  As a
-- result these timestamps /are not/ pure values, their meaning is
-- time-dependent!  They depend on the present time and are both at most
-- approximately +\/-68 years from the present.  This ambiguity is not a
-- problem because cached RRSIG records should only persist a few days,
-- signature lifetimes should be *much* shorter than 68 years, and key rotation
-- should result any misconstrued 136-year-old signatures fail to validate.
-- This also means that the interpretation of a time that is exactly half-way
-- around the clock at @now +\/-0x80000000@ is not important, the signature
-- should never be valid.
--
-- The upshot for us is that we need to convert these *impure* relative values
-- to pure absolute values at the moment they are received from from the network
-- (or read from files, ... in some impure I/O context), and convert them back to
-- 32-bit values when encoding.  Therefore, the constructor takes absolute
-- 64-bit representations of the inception and expiration times.
--
-- The 'dnsTime' function performs the requisite conversion.
data RD_RRSIG = RD_RRSIG
    { rrsig_type       :: TYPE
    -- ^ RRtype of RRset signed
    , rrsig_pubalg     :: PubAlg
    -- ^ DNSKEY algorithm
    , rrsig_num_labels :: Word8
    -- ^ Number of labels signed
    , rrsig_ttl        :: TTL
    -- ^ Maximum origin TTL
    , rrsig_expiration :: DNSTime
    -- ^ Time last valid
    , rrsig_inception  :: DNSTime
    -- ^ Time first valid
    , rrsig_key_tag    :: Word16
    -- ^ Signing key tag
    , rrsig_zone       :: Domain
    -- ^ Signing domain
    , rrsig_signature  :: Opaque
    -- ^ Opaque signature
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_RRSIG where
    resourceDataType _ = RRSIG
    resourceDataSize RD_RRSIG{..} =
        2 -- TYPE
            + 1 -- pubalg
            + 1 -- num labes
            + 4 -- seconds
            + 4 -- dns time
            + 4 -- dns time
            + 2 -- key_tag
            + domainSize rrsig_zone
            + Opaque.length rrsig_signature
    putResourceData cf RD_RRSIG{..} = \wbuf ref -> do
        putTYPE rrsig_type wbuf ref
        putPubAlg rrsig_pubalg wbuf ref
        put8 wbuf rrsig_num_labels
        putSeconds rrsig_ttl wbuf ref
        putDNSTime rrsig_expiration wbuf ref
        putDNSTime rrsig_inception wbuf ref
        put16 wbuf rrsig_key_tag
        putDomain cf rrsig_zone wbuf ref
        putOpaque rrsig_signature wbuf ref

{- FOURMOLU_DISABLE -}
get_rrsig :: Int -> Parser RD_RRSIG
get_rrsig lim rbuf ref = do
    -- The signature follows a variable length zone name
    -- and occupies the rest of the RData.  Simplest to
    -- checkpoint the position at the start of the RData,
    -- and after reading the zone name, and subtract that
    -- from the RData length.
    end <- rdataEnd lim rbuf ref
    rrsig_type       <- getTYPE rbuf ref
    rrsig_pubalg     <- getPubAlg rbuf ref
    rrsig_num_labels <- get8 rbuf
    rrsig_ttl        <- getSeconds rbuf ref
    rrsig_expiration <- getDNSTime rbuf ref
    rrsig_inception  <- getDNSTime rbuf ref
    rrsig_key_tag    <- get16 rbuf
    rrsig_zone       <- getDomain rbuf ref -- XXX: Enforce no compression?
    pos <- position rbuf
    rrsig_signature  <- getOpaque (end - pos) rbuf ref
    return RD_RRSIG{..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_rrsig
    :: TYPE
    -> PubAlg
    -> Word8
    -> TTL
    -> DNSTime
    -> DNSTime
    -> Word16
    -> Domain
    -> Opaque
    -> RData
rd_rrsig a b c d e f g h i = toRData $ RD_RRSIG a b c d e f g h i

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | Delegation Signer (RFC4034)
data RD_DS = RD_DS
    { ds_key_tag   :: Word16
    , ds_pubalg    :: PubAlg
    , ds_digestalg :: DigestAlg
    , ds_digest    :: Opaque
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_DS where
    resourceDataType _ = DS
    resourceDataSize RD_DS{..} =
        2
            + 1
            + 1
            + Opaque.length ds_digest
    putResourceData _ RD_DS{..} = \wbuf ref -> do
        put16 wbuf ds_key_tag
        putPubAlg ds_pubalg wbuf ref
        putDigestAlg ds_digestalg wbuf ref
        putOpaque ds_digest wbuf ref

{- FOURMOLU_DISABLE -}
get_ds :: Int -> Parser RD_DS
get_ds len rbuf ref = do
    ds_key_tag   <- get16 rbuf
    ds_pubalg    <- getPubAlg rbuf ref
    ds_digestalg <- getDigestAlg rbuf ref
    ds_digest    <- getOpaque (len - 4) rbuf ref
    return RD_DS {..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_ds :: Word16 -> PubAlg -> DigestAlg -> Opaque -> RData
rd_ds a b c d = toRData $ RD_DS a b c d

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | DNSSEC denial of existence NSEC record
data RD_NSEC = RD_NSEC
    { nsec_next_domain :: Domain
    , nsec_types       :: [TYPE]
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_NSEC where
    resourceDataType _ = NSEC
    resourceDataSize RD_NSEC{..} =
        domainSize nsec_next_domain
            + sum (map (\(_, l, _) -> l + 2) $ groupType nsec_types)
    putResourceData cf RD_NSEC{..} = \wbuf ref -> do
        _ <- putDomain cf nsec_next_domain wbuf ref
        putNsecTypes nsec_types wbuf ref

{- FOURMOLU_DISABLE -}
get_nsec :: Int -> Parser RD_NSEC
get_nsec len rbuf ref = do
    end <- rdataEnd len rbuf ref
    nsec_next_domain <- getDomain rbuf ref
    pos <- position rbuf
    nsec_types       <- getNsecTypes (end - pos) rbuf ref
    return RD_NSEC {..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_nsec :: Domain -> [TYPE] -> RData
rd_nsec a b = toRData $ RD_NSEC a b

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | DNSKEY (RFC4034)
data RD_DNSKEY = RD_DNSKEY
    { dnskey_flags      :: [DNSKEY_Flag]
    , dnskey_protocol   :: Word8
    , dnskey_pubalg     :: PubAlg
    , dnskey_public_key :: PubKey
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_DNSKEY where
    resourceDataType _ = DNSKEY
    resourceDataSize RD_DNSKEY{..} =
        2 + 1 + 1 + Opaque.length (fromPubKey dnskey_public_key)
    putResourceData _ RD_DNSKEY{..} = \wbuf ref -> do
        putDNSKEYflags dnskey_flags wbuf ref
        put8 wbuf dnskey_protocol
        putPubAlg dnskey_pubalg wbuf ref
        putPubKey dnskey_public_key wbuf ref

{- FOURMOLU_DISABLE -}
get_dnskey :: Int -> Parser RD_DNSKEY
get_dnskey len rbuf ref = do
    dnskey_flags      <- getDNSKEYflags rbuf ref
    dnskey_protocol   <- get8 rbuf
    dnskey_pubalg     <- getPubAlg rbuf ref
    dnskey_public_key <- getPubKey dnskey_pubalg (len - 4) rbuf ref
    return RD_DNSKEY{..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_dnskey :: [DNSKEY_Flag] -> Word8 -> PubAlg -> PubKey -> RData
rd_dnskey a b c d = toRData $ RD_DNSKEY a b c d

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | DNSSEC hashed denial of existence (RFC5155)
data RD_NSEC3 = RD_NSEC3
    { nsec3_hashalg                :: HashAlg
    , nsec3_flags                  :: [NSEC3_Flag]
    , nsec3_iterations             :: Word16
    , nsec3_salt                   :: Opaque
    , nsec3_next_hashed_owner_name :: Opaque
    , nsec3_types                  :: [TYPE]
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_NSEC3 where
    resourceDataType _ = NSEC3
    resourceDataSize RD_NSEC3{..} =
        1
            + 1 -- hash alg
            + 2 -- flags
            + 1
            + Opaque.length nsec3_salt
            + 1
            + Opaque.length nsec3_next_hashed_owner_name
            + sum (map (\(_, l, _) -> l + 2) $ groupType nsec3_types)
    putResourceData _ RD_NSEC3{..} = \wbuf ref -> do
        putHashAlg nsec3_hashalg wbuf ref
        putNSEC3flags nsec3_flags wbuf ref
        put16 wbuf nsec3_iterations
        putLenOpaque nsec3_salt wbuf ref
        putLenOpaque nsec3_next_hashed_owner_name wbuf ref
        putNsecTypes nsec3_types wbuf ref

{- FOURMOLU_DISABLE -}
get_nsec3 :: Int -> Parser RD_NSEC3
get_nsec3 len rbuf ref = do
    dend <- rdataEnd len rbuf ref
    nsec3_hashalg                <- getHashAlg rbuf ref
    nsec3_flags                  <- getNSEC3flags rbuf ref
    nsec3_iterations             <- get16 rbuf
    nsec3_salt                   <- getLenOpaque rbuf ref
    nsec3_next_hashed_owner_name <- getLenOpaque rbuf ref
    tpos <- position rbuf
    nsec3_types                  <- getNsecTypes (dend - tpos) rbuf ref
    return RD_NSEC3{..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_nsec3
    :: HashAlg -> [NSEC3_Flag] -> Word16 -> Opaque -> Opaque -> [TYPE] -> RData
rd_nsec3 a b c d e f = toRData $ RD_NSEC3 a b c d e f

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | NSEC3 zone parameters (RFC5155)
data RD_NSEC3PARAM = RD_NSEC3PARAM
    { nsec3param_hashalg    :: HashAlg
    , nsec3param_flags      :: Word8
    , nsec3param_iterations :: Word16
    , nsec3param_salt       :: Opaque
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_NSEC3PARAM where
    resourceDataType _ = NSEC3PARAM
    resourceDataSize RD_NSEC3PARAM{..} =
        1 + 1 + 2 + (1 + Opaque.length nsec3param_salt)
    putResourceData _ RD_NSEC3PARAM{..} = \wbuf ref -> do
        putHashAlg nsec3param_hashalg wbuf ref
        put8 wbuf nsec3param_flags
        put16 wbuf nsec3param_iterations
        putLenOpaque nsec3param_salt wbuf ref

{- FOURMOLU_DISABLE -}
get_nsec3param :: Int -> Parser RD_NSEC3PARAM
get_nsec3param _ rbuf ref = do
    nsec3param_hashalg    <- getHashAlg rbuf ref
    nsec3param_flags      <- get8 rbuf
    nsec3param_iterations <- get16 rbuf
    nsec3param_salt       <- getLenOpaque rbuf ref
    return RD_NSEC3PARAM {..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_nsec3param :: HashAlg -> Word8 -> Word16 -> Opaque -> RData
rd_nsec3param a b c d = toRData $ RD_NSEC3PARAM a b c d

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | Child DS (RFC7344)
data RD_CDS = RD_CDS
    { cds_key_tag   :: Word16
    , cds_pubalg    :: PubAlg
    , cds_digestalg :: DigestAlg
    , cds_digest    :: Opaque
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_CDS where
    resourceDataType _ = CDS
    resourceDataSize RD_CDS{..} =
        2
            + 1
            + 1
            + Opaque.length cds_digest
    putResourceData _ RD_CDS{..} = \wbuf ref -> do
        put16 wbuf cds_key_tag
        putPubAlg cds_pubalg wbuf ref
        putDigestAlg cds_digestalg wbuf ref
        putOpaque cds_digest wbuf ref

{- FOURMOLU_DISABLE -}
get_cds :: Int -> Parser RD_CDS
get_cds len rbuf ref = do
    cds_key_tag   <- get16 rbuf
    cds_pubalg    <- getPubAlg rbuf ref
    cds_digestalg <- getDigestAlg rbuf ref
    cds_digest    <- getOpaque (len - 4) rbuf ref
    return RD_CDS {..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_cds :: Word16 -> PubAlg -> DigestAlg -> Opaque -> RData
rd_cds a b c d = toRData $ RD_CDS a b c d

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | Child DNSKEY (RFC7344)
data RD_CDNSKEY = RD_CDNSKEY
    { cdnskey_flags      :: [DNSKEY_Flag]
    , cdnskey_protocol   :: Word8
    , cdnskey_pubalg     :: PubAlg
    , cdnskey_public_key :: PubKey
    }
    deriving (Eq, Ord, Show)
{- FOURMOLU_ENABLE -}

instance ResourceData RD_CDNSKEY where
    resourceDataType _ = CDNSKEY
    resourceDataSize RD_CDNSKEY{..} =
        2 + 1 + 1 + Opaque.length (fromPubKey cdnskey_public_key)
    putResourceData _ RD_CDNSKEY{..} = \wbuf ref -> do
        putDNSKEYflags cdnskey_flags wbuf ref
        put8 wbuf cdnskey_protocol
        putPubAlg cdnskey_pubalg wbuf ref
        putPubKey cdnskey_public_key wbuf ref

{- FOURMOLU_DISABLE -}
get_cdnskey :: Int -> Parser RD_CDNSKEY
get_cdnskey len rbuf ref = do
    cdnskey_flags      <- getDNSKEYflags rbuf ref
    cdnskey_protocol   <- get8 rbuf
    cdnskey_pubalg     <- getPubAlg rbuf ref
    cdnskey_public_key <- getPubKey cdnskey_pubalg (len - 4) rbuf ref
    return RD_CDNSKEY {..}
{- FOURMOLU_ENABLE -}

-- | Smart constructor.
rd_cdnskey :: [DNSKEY_Flag] -> Word8 -> PubAlg -> PubKey -> RData
rd_cdnskey a b c d = toRData $ RD_CDNSKEY a b c d

----------------------------------------------------------------

rdataEnd
    :: Int
    -- ^ number of bytes left from current position
    -> Parser Int
    -- ^ end position
rdataEnd lim rbuf _ = (+) lim <$> position rbuf

----------------------------------------------------------------

bitmapSize :: Int -> Int
bitmapSize x = (x `unsafeShiftR` 3) + 1

-- | Getting [(Window Block #, Bitmap Length, [Bit])]
--
-- >>> groupType [NS,DS,RRSIG,NSEC]
-- [(0,6,[2,43,46,47])]
-- >>> groupType [A,AAAA,TYPE 1000,TYPE 1001]
-- [(0,4,[1,28]),(3,30,[232,233])]
groupType :: [TYPE] -> [(Word8, Int, [Int])]
groupType ts = go id ts
  where
    divide :: TYPE -> (Word8, Int)
    divide t =
        let t' = fromTYPE t
            window = fromIntegral (t' `unsafeShiftR` 8)
            bot8 = fromIntegral (t' .&. 0xff)
         in (window, bot8)
    go obd [] = obd []
    go obd (x : xs) = spn obd w b id xs
      where
        (w, b) = divide x
    spn obd w0 b0 ibd [] = (obd . ((w0, bitmapSize b0, ibd [b0]) :)) []
    spn obd w0 b0 ibd (x : xs)
        | w0 == w = spn obd w0 b (ibd . (b0 :)) xs
        | otherwise = spn (obd . ((w0, bitmapSize b0, ibd [b0]) :)) w b id xs
      where
        (w, b) = divide x

makeBitmap :: Int -> [Int] -> Array Int Word8
makeBitmap len bs = runSTArray $ do
    arr <- newArray (0, len - 1) 0
    mapM_ (setBitmap arr) bs
    return arr
  where
    setBitmap arr n = do
        let i = n `unsafeShiftR` 3
            pos = 7 - (n .&. 0x7)
        x <- readArray arr i
        let x' = x `setBit` pos
        writeArray arr i x'

-- | Encode DNSSEC NSEC type bits
putNsecTypes :: [TYPE] -> Builder ()
putNsecTypes ts wbuf _ = mapM_ putTypeBitMap $ groupType ts
  where
    putTypeBitMap (window, len, bs) = do
        put8 wbuf window
        putInt8 wbuf len
        mapM_ (put8 wbuf) (makeBitmap len bs)

-- <https://tools.ietf.org/html/rfc4034#section-4.1>
-- Parse a list of NSEC type bitmaps
--
getNsecTypes :: Int -> Parser [TYPE]
getNsecTypes len rbuf ref = concat <$> sGetMany "NSEC type bitmap" len getbits rbuf ref
  where
    getbits _ _ = do
        window <- flip shiftL 8 <$> getInt8 rbuf
        blocks <- getInt8 rbuf
        when (blocks > 32) $
            failParser $
                "NSEC bitmap block too long: " ++ show blocks
        concatMap blkTypes . zip [window, window + 8 ..] <$> getNBytes rbuf blocks
      where
        blkTypes (bitOffset, byte) =
            [ toTYPE $ fromIntegral $ bitOffset + i
            | i <- [0 .. 7]
            , byte .&. bit (7 - i) /= 0
            ]
