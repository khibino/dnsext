-- | DNS message decoders.
--
-- When in doubt, use the 'decodeAt' function, which correctly handle
-- /circle-arithmetic/ DNS timestamps, e.g., in @RRSIG@ resource
-- records.  The 'decode' functionsare only appropriate in pure
-- contexts when the current time is not available, and @RRSIG@
-- records are not expected or desired.
module DNS.Types.Decode (
    -- * Decoding a single DNS message
    decodeAt,
    decode,

    -- * Decoders for parts
    decodeDNSFlags,
    decodeQuestion,
    decodeResourceRecordAt,
    decodeResourceRecord,
    decodeRData,
    decodeDomain,
    decodeMailbox,
) where

import qualified Data.ByteString as BS

import DNS.Types.Dict
import DNS.Types.Domain
import DNS.Types.Error
import DNS.Types.Imports
import DNS.Types.Message
import DNS.Types.RData
import DNS.Types.Time
import DNS.Types.Type
import DNS.Wire

----------------------------------------------------------------

-- | Decode an input buffer containing a single encoded DNS message.  If the
-- input buffer has excess content beyond the end of the message an error is
-- returned.  DNS /circle-arithmetic/ timestamps (e.g. in RRSIG records) are
-- interpreted at the supplied epoch time.
decodeAt
    :: EpochTime
    -- ^ current epoch time
    -> ByteString
    -- ^ encoded input buffer
    -> Either DNSError DNSMessage
    -- ^ decoded message or error
decodeAt t bs = runParserAt t getDNSMessage bs

-- | Decode an input buffer containing a single encoded DNS message.  If the
-- input buffer has excess content beyond the end of the message an error is
-- returned.  DNS /circle-arithmetic/ timestamps (e.g. in RRSIG records) are
-- interpreted based on a nominal time in the year 2073 chosen to maximize
-- the time range for which this gives correct translations of 32-bit epoch
-- times to absolute 64-bit epoch times.  This will yield incorrect results
-- starting circa 2141.
decode
    :: ByteString
    -- ^ encoded input buffer
    -> Either DNSError DNSMessage
    -- ^ decoded message or error
decode bs = runParser getDNSMessage bs

----------------------------------------------------------------

-- | Decode DNS flags.
decodeDNSFlags :: ByteString -> Either DNSError (DNSFlags, OPCODE, RCODE)
decodeDNSFlags bs = runParser getDNSFlags bs

-- | Decode a question.
decodeQuestion :: ByteString -> Either DNSError Question
decodeQuestion bs = runParser getQuestion bs

-- | Decoding a resource record.

-- | Decode a resource record (RR) with any DNS timestamps interpreted at the
-- nominal epoch time (see 'decodeAt').  Since RRs may use name compression,
-- it is not generally possible to decode resource record separately from the
-- enclosing DNS message.  This is an internal function.
decodeResourceRecord :: ByteString -> Either DNSError ResourceRecord
decodeResourceRecord bs = runParser getResourceRecord bs

-- | Decode a resource record with DNS timestamps interpreted at the
-- supplied epoch time.  Since RRs may use DNS name compression, it is not
-- generally possible to decode resource record separately from the enclosing
-- DNS message.  This is an internal function.
decodeResourceRecordAt
    :: EpochTime
    -- ^ current epoch time
    -> ByteString
    -- ^ encoded resource record
    -> Either DNSError ResourceRecord
decodeResourceRecordAt t bs = runParserAt t getResourceRecord bs

-- | Decode a resource data.
decodeRData :: TYPE -> ByteString -> Either DNSError RData
decodeRData typ bs = runParser (getRData typ len) bs
  where
    len = BS.length bs

-- | Decode a domain name.  Since DNS names may use name compression, it is not
-- generally possible to decode the names separately from the enclosing DNS
-- message.  This is an internal function exposed only for testing.
decodeDomain :: ByteString -> Either DNSError Domain
decodeDomain bs = runParser getDomain bs

-- | Decode a mailbox name (e.g. the SOA record /rname/ field).  Since DNS names
-- may use name compression, it is not generally possible to decode the names
-- separately from the enclosing DNS message.  This is an internal function.
decodeMailbox :: ByteString -> Either DNSError Mailbox
decodeMailbox bs = runParser getMailbox bs
