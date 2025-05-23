{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE PatternSynonyms #-}

module DNS.Types.EDNS (
    EDNS (..),
    defaultEDNS,
    OptCode (
        OptCode,
        NSID,
        ClientSubnet,
        Padding,
        EDNSError
    ),
    fromOptCode,
    toOptCode,
    odataToOptCode,
    OptData (..),
    fromOData,
    toOData,
    odataSize,
    putOData,
    OData (..),
    OD_NSID (..),
    OD_ClientSubnet (..),
    OD_Padding (..),
    get_nsid,
    get_clientSubnet,
    get_padding,
    get_ednsError,
    od_nsid,
    od_clientSubnet,
    od_ecsGeneric,
    od_padding,
    od_ednsError,
    od_unknown,
    addOpt,
) where

import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import Data.Char (toUpper)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.IP (IP (..), fromIPv4, fromIPv6b, makeAddrRange, toIPv4, toIPv6b)
import qualified Data.IP (addr)
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IM
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import System.IO.Unsafe (unsafePerformIO)
import Text.Read

import DNS.Types.Imports
import DNS.Types.Opaque.Internal (Opaque, getOpaque, putOpaque)
import qualified DNS.Types.Opaque.Internal as Opaque
import DNS.Wire

----------------------------------------------------------------
-- EDNS (RFC 6891, EDNS(0))
----------------------------------------------------------------

-- | EDNS information defined in RFC 6891.
data EDNS = EDNS
    { ednsVersion :: Word8
    -- ^ EDNS version, presently only version 0 is defined.
    , ednsUdpSize :: Word16
    -- ^ Supported UDP payload size.
    , ednsDnssecOk :: Bool
    -- ^ Request DNSSEC replies (with RRSIG and NSEC records as as appropriate)
    -- from the server.  Generally, not needed (except for diagnostic purposes)
    -- unless the signatures will be validated.  Just setting the 'AD' bit in
    -- the query and checking it in the response is sufficient (but often
    -- subject to man-in-the-middle forgery) if all that's wanted is whether
    -- the server validated the response.
    , ednsOptions :: [OData]
    -- ^ EDNS options (e.g. 'OD_NSID', 'OD_ClientSubnet', ...)
    }
    deriving (Eq, Show)

-- | The default EDNS pseudo-header for queries.  The UDP buffer size is set to
--   1216 bytes, which should result in replies that fit into the 1280 byte
--   IPv6 minimum MTU.  Since IPv6 only supports fragmentation at the source,
--   and even then not all gateways forward IPv6 pre-fragmented IPv6 packets,
--   it is best to keep DNS packet sizes below this limit when using IPv6
--   nameservers.  A larger value may be practical when using IPv4 exclusively.
--
-- @
-- defaultEDNS = EDNS
--     { ednsVersion = 0      -- The default EDNS version is 0
--     , ednsUdpSize = 1232   -- IPv6-safe UDP MTU (RIPE recommendation)
--     , ednsDnssecOk = False -- We don't do DNSSEC validation
--     , ednsOptions = []     -- No EDNS options by default
--     }
-- @
defaultEDNS :: EDNS
defaultEDNS =
    EDNS
        { ednsVersion = 0 -- The default EDNS version is 0
        , ednsUdpSize = 1232 -- IPv6-safe UDP MTU (1280 - 40 - 8)
        , ednsDnssecOk = False -- We don't do DNSSEC validation
        , ednsOptions = [] -- No EDNS options by default
        }

----------------------------------------------------------------

-- | EDNS Option Code (RFC 6891).
newtype OptCode = OptCode
    { fromOptCode :: Word16
    -- ^ From option code to number.
    }
    deriving (Eq, Ord)

-- | From number to option code.
toOptCode :: Word16 -> OptCode
toOptCode = OptCode

-- | NSID (RFC5001, section 2.3)
pattern NSID :: OptCode
pattern NSID = OptCode 3

-- | Client subnet (RFC7871)
pattern ClientSubnet :: OptCode
pattern ClientSubnet = OptCode 8

-- | Padding (RFC7830)
pattern Padding :: OptCode
pattern Padding = OptCode 12

pattern EDNSError :: OptCode
pattern EDNSError = OptCode 15

----------------------------------------------------------------

instance Show OptCode where
    show (OptCode w) = case IM.lookup i dict of
        Nothing -> "OptCode " ++ show w
        Just name -> name
      where
        i = fromIntegral w
        dict = unsafePerformIO $ readIORef globalOptShowDict

type OptShowDict = IntMap String

insertOptShowDict :: OptCode -> String -> OptShowDict -> OptShowDict
insertOptShowDict (OptCode w) name dict = IM.insert i name dict
  where
    i = fromIntegral w

defaultOptShowDict :: OptShowDict
defaultOptShowDict =
    insertOptShowDict NSID "NSID" $
        insertOptShowDict
            ClientSubnet
            "ClientSubnet"
            IM.empty

{-# NOINLINE globalOptShowDict #-}
globalOptShowDict :: IORef OptShowDict
globalOptShowDict = unsafePerformIO $ newIORef defaultOptShowDict

instance Read OptCode where
    readListPrec = readListPrecDefault
    readPrec = do
        ms <- lexP
        let str0 = case ms of
                Ident s -> s
                String s -> s
                _ -> fail "Read OptCode"
            str = map toUpper str0
            dict = unsafePerformIO $ readIORef globalOptReadDict
        case M.lookup str dict of
            Just t -> return t
            _ -> fail "Read OptCode"

type OptReadDict = Map String OptCode

insertOptReadDict :: OptCode -> String -> OptReadDict -> OptReadDict
insertOptReadDict o name dict = M.insert name o dict

defaultOptReadDict :: OptReadDict
defaultOptReadDict =
    insertOptReadDict NSID "NSID" $
        insertOptReadDict
            ClientSubnet
            "ClientSubnet"
            M.empty

{-# NOINLINE globalOptReadDict #-}
globalOptReadDict :: IORef OptReadDict
globalOptReadDict = unsafePerformIO $ newIORef defaultOptReadDict

addOpt :: OptCode -> String -> IO ()
addOpt code name = do
    atomicModifyIORef' globalOptShowDict insShow
    atomicModifyIORef' globalOptReadDict insRead
  where
    insShow dict = (insertOptShowDict code name dict, ())
    insRead dict = (insertOptReadDict code name dict, ())

---------------------------------------------------------------

class (Typeable a, Eq a, Show a) => OptData a where
    optDataCode :: a -> OptCode
    optDataSize :: a -> Int
    putOptData :: a -> Builder ()

---------------------------------------------------------------

-- | A type to uniform 'OptData' 'a'.
data OData = forall a. OptData a => OData a

-- | Extracting the original type.
fromOData :: Typeable a => OData -> Maybe a
fromOData (OData x) = cast x

-- | Wrapping the original type with 'OData'.
toOData :: OptData a => a -> OData
toOData = OData

odataSize :: OData -> Int
odataSize (OData o) = optDataSize o

instance Show OData where
    show (OData x) = show x

instance Eq OData where
    x@(OData xi) == y@(OData yi) = typeOf x == typeOf y && Just xi == cast yi

-- | Getting 'OptCode' of 'OData'.
odataToOptCode :: OData -> OptCode
odataToOptCode (OData x) = optDataCode x

putOData :: OData -> Builder ()
putOData (OData x) = putOptData x

---------------------------------------------------------------

-- | Name Server Identifier (RFC5001).  Bidirectional, empty from client.
-- (opaque octet-string).  May contain binary data, which MUST be empty
-- in queries.
newtype OD_NSID = OD_NSID Opaque deriving (Eq)

instance Show OD_NSID where
    show = _showNSID

instance OptData OD_NSID where
    optDataCode _ = NSID
    optDataSize (OD_NSID nsid) = Opaque.length nsid
    putOptData (OD_NSID nsid) = putODBytes (fromOptCode NSID) nsid

get_nsid :: Int -> Parser OD_NSID
get_nsid len rbuf _ = OD_NSID . Opaque.fromShortByteString <$> getNShortByteString rbuf len

od_nsid :: Opaque -> OData
od_nsid = toOData . OD_NSID

---------------------------------------------------------------

-- | ECS(EDNS client subnet) (RFC7871).
data OD_ClientSubnet
    = -- | Valid client subnet.
      --   Bidirectional. (source bits, scope bits, address).
      --   The address is masked and truncated when encoding queries.
      --   The address is zero-padded when decoding.
      OD_ClientSubnet Word8 Word8 IP
    | -- | Unsupported or malformed IP client subnet option.  Bidirectional.
      --   (address family, source bits, scope bits, opaque address).
      OD_ECSgeneric Word16 Word8 Word8 Opaque
    deriving (Eq)

instance Show OD_ClientSubnet where
    show (OD_ClientSubnet b1 b2 ip@(IPv4 _)) = _showECS 1 b1 b2 $ show ip
    show (OD_ClientSubnet b1 b2 ip@(IPv6 _)) = _showECS 2 b1 b2 $ show ip
    show (OD_ECSgeneric fam b1 b2 a) = _showECS fam b1 b2 $ C8.unpack $ Opaque.toBase16 a

instance OptData OD_ClientSubnet where
    optDataCode _ = ClientSubnet
    optDataSize (OD_ClientSubnet _ _ (IPv4 _)) = 6
    optDataSize (OD_ClientSubnet _ _ (IPv6 _)) = 18
    optDataSize (OD_ECSgeneric _ _ _ o) = 4 + Opaque.length o
    putOptData = put_clientSubnet

put_clientSubnet :: OD_ClientSubnet -> Builder ()
put_clientSubnet (OD_ClientSubnet srcBits scpBits ip) wbuf _ =
    -- https://tools.ietf.org/html/rfc7871#section-6
    --
    -- o  ADDRESS, variable number of octets, contains either an IPv4 or
    --    IPv6 address, depending on FAMILY, which MUST be truncated to the
    --    number of bits indicated by the SOURCE PREFIX-LENGTH field,
    --    padding with 0 bits to pad to the end of the last octet needed.
    --
    -- o  A server receiving an ECS option that uses either too few or too
    --    many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
    --    SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
    --    as a signal to the software developer making the request to fix
    --    their implementation.
    --
    let octets = fromIntegral $ (srcBits + 7) `div` 8
        prefix addr = Data.IP.addr $ makeAddrRange addr $ fromIntegral srcBits
        (family, raw) = case ip of
            IPv4 ip4 -> (1, take octets $ fromIPv4 $ prefix ip4)
            IPv6 ip6 -> (2, take octets $ fromIPv6b $ prefix ip6)
        dataLen = 2 + 2 + octets
     in do
            put16 wbuf $ fromOptCode ClientSubnet
            putInt16 wbuf dataLen
            put16 wbuf family
            put8 wbuf srcBits
            put8 wbuf scpBits
            mapM_ (putInt8 wbuf) raw
put_clientSubnet (OD_ECSgeneric family srcBits scpBits addr) wbuf ref = do
    put16 wbuf $ fromOptCode ClientSubnet
    putInt16 wbuf $ 4 + Opaque.length addr
    put16 wbuf family
    put8 wbuf srcBits
    put8 wbuf scpBits
    putOpaque addr wbuf ref

get_clientSubnet :: Int -> Parser OD_ClientSubnet
get_clientSubnet len rbuf ref = do
    family <- get16 rbuf
    srcBits <- get8 rbuf
    scpBits <- get8 rbuf
    addr <- getOpaque (len - 4) rbuf ref -- 4 = 2 + 1 + 1
    --
    -- https://tools.ietf.org/html/rfc7871#section-6
    --
    -- o  ADDRESS, variable number of octets, contains either an IPv4 or
    --    IPv6 address, depending on FAMILY, which MUST be truncated to the
    --    number of bits indicated by the SOURCE PREFIX-LENGTH field,
    --    padding with 0 bits to pad to the end of the last octet needed.
    --
    -- o  A server receiving an ECS option that uses either too few or too
    --    many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
    --    SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
    --    as a signal to the software developer making the request to fix
    --    their implementation.
    --
    -- In order to avoid needless decoding errors, when the ECS encoding
    -- requirements are violated, we construct an OD_ECSgeneric OData,
    -- instread of an IP-specific OD_ClientSubnet OData, which will only
    -- be used for valid inputs.  When the family is neither IPv4(1) nor
    -- IPv6(2), or the address prefix is not correctly encoded (too long
    -- or too short), the OD_ECSgeneric data contains the verbatim input
    -- from the peer.
    --
    let addrbs = Opaque.toShortByteString addr
    case Short.length addrbs == (fromIntegral srcBits + 7) `div` 8 of
        True
            | Just ip <- bstoip family addrbs srcBits scpBits ->
                pure $ OD_ClientSubnet srcBits scpBits ip
        _ -> pure $ OD_ECSgeneric family srcBits scpBits addr
  where
    prefix addr bits = Data.IP.addr $ makeAddrRange addr $ fromIntegral bits
    zeropad = (++ repeat 0) . map fromIntegral . Short.unpack
    checkBits fromBytes toIP srcBits scpBits bytes =
        let addr = fromBytes bytes
            maskedAddr = prefix addr srcBits
            maxBits = fromIntegral $ 8 * length bytes
         in if addr == maskedAddr && scpBits <= maxBits
                then Just $ toIP addr
                else Nothing
    bstoip :: Word16 -> ShortByteString -> Word8 -> Word8 -> Maybe IP
    bstoip family bs srcBits scpBits = case family of
        1 -> checkBits toIPv4 IPv4 srcBits scpBits $ take 4 $ zeropad bs
        2 -> checkBits toIPv6b IPv6 srcBits scpBits $ take 16 $ zeropad bs
        _ -> Nothing

od_clientSubnet :: Word8 -> Word8 -> IP -> OData
od_clientSubnet a b c = toOData $ OD_ClientSubnet a b c

od_ecsGeneric :: Word16 -> Word8 -> Word8 -> Opaque -> OData
od_ecsGeneric a b c d = toOData $ OD_ECSgeneric a b c d

---------------------------------------------------------------

-- | The EDNS(0) Padding Option (RFC7830)
newtype OD_Padding = OD_Padding Opaque deriving (Eq)

instance Show OD_Padding where
    show (OD_Padding o) = "Padding(" ++ show (Opaque.length o) ++ ")"

instance OptData OD_Padding where
    optDataCode _ = Padding
    optDataSize (OD_Padding o) = Opaque.length o
    putOptData (OD_Padding o) = putODBytes (fromOptCode Padding) o

get_padding :: Int -> Parser OD_Padding
get_padding len rbuf _ = OD_Padding . Opaque.fromShortByteString <$> getNShortByteString rbuf len

od_padding :: Opaque -> OData
od_padding = toOData . OD_Padding

---------------------------------------------------------------

-- | Extended DNS Errors (RFC8914)
data OD_EDNSError = OD_EDNSError Word16 Opaque deriving (Eq)

{- FOURMOLU_DISABLE -}
instance Show OD_EDNSError where
    show (OD_EDNSError infoc txt) =
        "EDNSError{" ++
        " info-code=" ++ show infoc ++
        " extra-text=" ++ show (Opaque.toString txt) ++ " [" ++ show txt ++ "]" ++
        " }"
{- FOURMOLU_ENABLE -}

instance OptData OD_EDNSError where
    optDataCode _ = EDNSError
    optDataSize = datasize_ednsError
    putOptData = put_ednsError

datasize_ednsError :: OD_EDNSError -> Int
datasize_ednsError (OD_EDNSError _ txt) = 2 + Opaque.length txt

put_ednsError :: OD_EDNSError -> Builder ()
put_ednsError od@(OD_EDNSError infoc txt) wbuf ref = do
    put16 wbuf (fromOptCode EDNSError)
    putInt16 wbuf $ datasize_ednsError od
    put16 wbuf infoc
    putOpaque txt wbuf ref

get_ednsError :: Int -> Parser OD_EDNSError
get_ednsError len rbuf ref = OD_EDNSError <$> get16 rbuf <*> getOpaque (len - 2) rbuf ref

od_ednsError :: Word16 -> Opaque -> OData
od_ednsError infoc txt = toOData $ OD_EDNSError infoc txt

---------------------------------------------------------------

-- | Generic EDNS option.
-- (numeric 'OptCode', opaque content)
data OD_Unknown = OD_Unknown Word16 Opaque deriving (Eq)

instance Show OD_Unknown where
    show (OD_Unknown code o) =
        "OD_Unknown " ++ show code ++ " " ++ show o

instance OptData OD_Unknown where
    optDataCode (OD_Unknown n _) = toOptCode n
    optDataSize (OD_Unknown _ o) = Opaque.length o
    putOptData (OD_Unknown code bs) = putODBytes code bs

od_unknown :: Word16 -> Opaque -> OData
od_unknown code o = toOData $ OD_Unknown code o

---------------------------------------------------------------

_showNSID :: OD_NSID -> String
_showNSID (OD_NSID nsid) =
    "NSID "
        ++ C8.unpack (Opaque.toBase16 nsid)
        ++ ";"
        ++ printable bs
  where
    bs = Opaque.toByteString nsid
    printable = map (\c -> if c < ' ' || c > '~' then '?' else c) . C8.unpack

_showECS :: Word16 -> Word8 -> Word8 -> String -> String
_showECS family srcBits scpBits address =
    show family
        ++ " "
        ++ show srcBits
        ++ " "
        ++ show scpBits
        ++ " "
        ++ address

---------------------------------------------------------------

-- | Encode an EDNS OPTION byte string.
putODBytes :: Word16 -> Opaque -> Builder ()
putODBytes code o wbuf ref = do
    put16 wbuf code
    putInt16 wbuf $ Opaque.length o
    putOpaque o wbuf ref
