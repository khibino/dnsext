{-# LANGUAGE PatternSynonyms #-}

module DNS.Do53.Cache (
    -- * cache interfaces
    empty,
    null,
    lookup,
    lookupEither,
    takeRRSet,
    insert,
    expires,
    size,
    stubLookup,
    stubInsert,
    Ranking (..),
    rankedAnswer,
    rankedAuthority,
    rankedAdditional,
    insertSetFromSection,
    insertSetEmpty,
    TYPE (NX),

    -- * handy interface
    insertRRs,

    -- * low-level interfaces
    Cache (..),
    Key,
    Question (..),
    Val (..),
    CRSet,
    extractRRSet,
    (<+),
    alive,
    member,
    dump,
    dumpKeys,
)
where

-- GHC packages
import Control.DeepSeq (liftRnf)
import Control.Monad (guard)
import Data.Either (partitionEithers)
import Data.Function (on)
import Data.List (group, groupBy, sortOn, uncons)
import Data.Maybe (isJust)
import Prelude hiding (lookup, null)

-- others
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ

-- dnsext packages
import DNS.SEC (RD_RRSIG, TYPE (RRSIG))
import DNS.Types (
    CLASS,
    DNSMessage,
    Domain,
    Question (..),
    RData,
    ResourceRecord (ResourceRecord),
    TTL,
 )
import qualified DNS.Types as DNS
import DNS.Types.Decode (EpochTime)
import DNS.Types.Internal (TYPE (..))

{- CRSet
   -  Left  - NXDOMAIN or NODATA, hold zone-domain delegation from
   -  Right (_:_, Nothing) - not empty RRSET, not verified
   -  Right (_:_, Just []) - not empty RRSET, verification failed
   -  Right (_:_, Just (_:_)) - not empty RRSET, verification succeeded -}
type CRSet = Either Domain ([RData], Maybe [RD_RRSIG])

---

-- Ranking data (section 5.4.1 of RFC2181 - Clarifications to the DNS Specification)
-- <https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1>

data Ranking
    = {- + Additional information from an authoritative answer,
           Data from the authority section of a non-authoritative answer,
           Additional information from non-authoritative answers. -}
      RankAdditional
    | {- + Data from the answer section of a non-authoritative answer, and
           non-authoritative data from the answer section of authoritative
           answers, -}
      RankAnswer
    | {- + Glue from a primary zone, or glue from a zone transfer, -}
      --
      {- + Data from the authority section of an authoritative answer, -}
      -- -- avoiding issue of authority section in reply with aa flag
      {- + The authoritative data included in the answer section of an
           authoritative reply. -}
      RankAuthAnswer
    {- + Data from a zone transfer, other than glue, -}
    --
    {- + Data from a primary zone file, other than glue data, -}
    --
    deriving (Eq, Ord, Show)

-- ranking, derived order, the lower the beter

rankedSection
    :: Ranking
    -> Ranking
    -> (DNSMessage -> [ResourceRecord])
    -> DNSMessage
    -> ([ResourceRecord], Ranking)
rankedSection authRank noauthRank section msg =
    (,) (section msg) $
        if DNS.authAnswer flags then authRank else noauthRank
  where
    flags = DNS.flags $ DNS.header msg

rankedAnswer :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAnswer =
    rankedSection
        RankAuthAnswer
        RankAnswer
        DNS.answer

rankedAuthority :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAuthority =
    rankedSection
        {- avoid security hole with authorized reply and authority section case.
           RankAdditional does not overwrite glue. -}
        RankAdditional
        RankAdditional
        DNS.authority

rankedAdditional :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAdditional =
    rankedSection
        RankAdditional
        RankAdditional
        DNS.additional

---

type Key = Question

data Val = Val CRSet Ranking deriving (Show)

data Cache = Cache (OrdPSQ Key EpochTime Val) Int {- max size -}

empty :: Int -> Cache
empty = Cache PSQ.empty

null :: Cache -> Bool
null (Cache psq _) = PSQ.null psq

lookup
    :: EpochTime
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Maybe ([ResourceRecord], Ranking)
lookup now dom typ cls = lookupAlive now result dom typ cls
  where
    result ttl (Val crs rank) = Just (extractRRSet dom typ cls ttl crs, rank)

-- when cache has EMPTY, returns SOA
lookupEither
    :: EpochTime
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Maybe
        ( Either ([ResourceRecord], Ranking) [ResourceRecord]
        , Ranking {- SOA or RRs, ranking -}
        )
lookupEither now dom typ cls cache = lookupAlive now result dom typ cls cache
  where
    result ttl (Val crs rank) = case crs of
        Left srcDom -> do
            sp <- lookupAlive now (soaResult ttl srcDom) srcDom SOA DNS.classIN cache {- EMPTY hit. empty ranking and SOA result. -}
            return (Left sp, rank)
        _ ->
            Just (Right $ extractRRSet dom typ DNS.classIN ttl crs, rank)
    soaResult ettl srcDom ttl (Val crs rank) =
        Just
            ( extractRRSet
                srcDom
                SOA
                DNS.classIN
                (ettl `min` ttl {- treated as TTL of empty data -})
                crs
            , rank
            )

lookupAlive
    :: EpochTime
    -> (TTL -> Val -> Maybe a)
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Maybe a
lookupAlive now mk dom typ cls = lookup_ mkAlive $ Question dom typ cls
  where
    mkAlive eol v = do
        ttl <- alive now eol
        mk ttl v

-- lookup interface for stub resolver
stubLookup :: Key -> Cache -> Maybe (EpochTime, CRSet)
stubLookup k = lookup_ result k
  where
    result eol (Val crs _) = Just (eol, crs)

lookup_
    :: (EpochTime -> Val -> Maybe a)
    -> Key
    -> Cache
    -> Maybe a
lookup_ mk k (Cache cache _) = do
    (eol, v) <- k `PSQ.lookup` cache
    mk eol v

insertRRs :: EpochTime -> [ResourceRecord] -> Ranking -> Cache -> Maybe Cache
insertRRs now rrs rank c = insertRRSet =<< takeRRSet rrs
  where
    insertRRSet rrset = rrset $ \key ttl cr -> insert now key ttl cr rank c

-- |
--   Insert RR-list example with error-handling
--
-- @
--    case insertSetFromSection rrList rank of
--      (errRRLists, rrsets) ->
--        ...
--        [ k (insert now) cache  -- insert Maybe action
--        | k <- rrsets
--        ]
--        ...
--        ... errRRLists ...  -- error handlings
-- @
--
--   Insert empty-RRSet example for negative cache
-- @
--    insertSetEmpty sdom dom typ ttl rank (insert now) cache  -- insert Maybe action
-- @
insert :: EpochTime -> Key -> TTL -> CRSet -> Ranking -> Cache -> Maybe Cache
insert now k@(Question dom typ cls) ttl crs rank cache@(Cache c xsz) =
    maybe sized withOldRank lookupRank
  where
    lookupRank =
        lookupAlive
            now
            (\_ (Val _ r) -> Just r)
            dom
            typ
            cls
            cache
    withOldRank r = do
        guard $ rank > r
        inserted -- replacing rank does not change size
    eol = now <+ ttl
    inserted = Just $ Cache (PSQ.insert k eol (Val crs rank) c) xsz
    sized
        | PSQ.size c < xsz = inserted
        | otherwise = do
            (_, l, _, deleted) <- PSQ.minView c
            guard $ eol > l -- Guard if the tried to insert has the smallest lifetime
            Just $ Cache (PSQ.insert k eol (Val crs rank) deleted) xsz

-- insert interface for stub resolver
stubInsert :: Key -> EpochTime -> CRSet -> Cache -> Maybe Cache
stubInsert k eol crs (Cache c xsz) =
    sized
  where
    rank = RankAnswer
    inserted = Just $ Cache (PSQ.insert k eol (Val crs rank) c) xsz
    sized
        | PSQ.size c < xsz = inserted
        | otherwise = do
            (_, l, _, deleted) <- PSQ.minView c
            guard $ eol > l -- Guard if the tried to insert has the smallest lifetime
            Just $ Cache (PSQ.insert k eol (Val crs rank) deleted) xsz

expires :: EpochTime -> Cache -> Maybe Cache
expires now (Cache c xsz) =
    case PSQ.findMin c of
        Just (_, eol, _)
            | eol <= now -> Just $ Cache (snd $ PSQ.atMostView now c) xsz
            | otherwise -> Nothing
        Nothing -> Nothing

alive :: EpochTime -> EpochTime -> Maybe TTL
alive now eol = do
    let ttl' = eol - now
        safeToTTL :: EpochTime -> Maybe TTL
        safeToTTL sec = do
            let y = fromIntegral sec
            guard $ toInteger y == toInteger sec
            return y
    guard $ ttl' >= 1
    safeToTTL ttl'

size :: Cache -> Int
size (Cache c _) = PSQ.size c

-- code from Reserved for Private Use (section 3.1 of RFC6895)
-- <https://datatracker.ietf.org/doc/html/rfc6895#section-3.1>

-- | Key for NameError
pattern NX :: TYPE
pattern NX = TYPE 0xff00

---
{- debug interfaces -}

member
    :: EpochTime
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Bool
member now dom typ cls = isJust . lookupAlive now (\_ _ -> Just ()) dom typ cls

dump :: Cache -> [(Key, (EpochTime, Val))]
dump (Cache c _) = [(k, (eol, v)) | (k, eol, v) <- PSQ.toAscList c]

dumpKeys :: Cache -> [(Key, EpochTime)]
dumpKeys (Cache c _) = [(k, eol) | (k, eol, _v) <- PSQ.toAscList c]

---

(<+) :: EpochTime -> TTL -> EpochTime
now <+ ttl = now + fromIntegral ttl

infixl 6 <+

toRDatas :: CRSet -> ([RData], [RD_RRSIG])
toRDatas (Left _) = ([], [])
toRDatas (Right (rs, sigs)) = (rs, maybe [] id sigs)

fromRDatas :: [RData] -> Maybe CRSet
fromRDatas [] = Nothing
fromRDatas rds = rds `listseq` Just (Right (rds, Nothing))
  where
    listRnf :: [a] -> ()
    listRnf = liftRnf (`seq` ())
    listseq :: [a] -> b -> b
    listseq ps q = case listRnf ps of () -> q

rrSetKey :: ResourceRecord -> Maybe (Key, TTL)
rrSetKey (ResourceRecord rrname rrtype rrclass rrttl rd)
    | rrclass == DNS.classIN
        && DNS.rdataType rd == rrtype =
        Just (Question rrname rrtype rrclass, rrttl)
    | otherwise = Nothing

takeRRSet :: [ResourceRecord] -> Maybe ((Key -> TTL -> CRSet -> a) -> a)
takeRRSet [] = Nothing
takeRRSet rrs@(_ : _) = do
    ps <- mapM rrSetKey rrs -- rrtype and rdata are consistent for each RR
    guard $ length (group ps) == 1 -- query key and TLL are equal for each elements
    (k', _) <- uncons ps -- always success because rrs is not null.
    rds <- fromRDatas $ map DNS.rdata rrs
    return $ \h -> uncurry h k' rds

{- FOURMOLU_DISABLE -}
extractRRSet :: Domain -> TYPE -> CLASS -> TTL -> CRSet -> [ResourceRecord]
extractRRSet dom ty cls ttl crs =
    [ResourceRecord dom ty cls ttl rd | rd <- rds] ++
    [ResourceRecord dom RRSIG cls ttl $ DNS.toRData sig | sig <- sigs]
  where
    (rds, sigs) = toRDatas crs
{- FOURMOLU_ENABLE -}

insertSetFromSection
    :: [ResourceRecord]
    -> Ranking
    -> ([[ResourceRecord]], [(Key -> TTL -> CRSet -> Ranking -> a) -> a])
insertSetFromSection rs0 r0 = (errRS, iset rrss r0)
  where
    key rr = (DNS.rrname rr, DNS.rrtype rr, DNS.rrclass rr)
    getRRSet rs = maybe (Left rs) Right $ takeRRSet rs
    (errRS, rrss) = partitionEithers . map getRRSet . groupBy ((==) `on` key) . sortOn key $ rs0
    iset ss rank = [\h -> rrset $ \k ttl cr -> h k ttl cr rank | rrset <- ss]

insertSetEmpty
    :: Domain
    -> Domain
    -> TYPE
    -> TTL
    -> Ranking
    -> ((Key -> TTL -> CRSet -> Ranking -> a) -> a)
insertSetEmpty srcDom dom typ ttl rank h = srcDom `seq` h key ttl (Left srcDom) rank
  where
    key = Question dom typ DNS.classIN
