{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.API (
    getResponseIterative,
    CacheResult (..),
    getResponseCached,
    getResultIterative,
    getResultCached,
    replyMessage,
) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (
    EdnsControls (..),
    FlagOp (..),
    HeaderControls (..),
    QueryControls (..),
 )
import qualified DNS.Do53.Client as DNS
import DNS.SEC (TYPE (..))
import DNS.Types hiding (InvalidEDNS)
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Resolve
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils (logQueryErrors)

-----

{- datatypes to propagate request flags -}

data RequestDO
    = DnssecOK
    | NoDnssecOK
    deriving (Show)

data RequestCD
    = CheckDisabled
    | NoCheckDisabled
    deriving (Show)

data RequestAD
    = AuthenticatedData
    | NoAuthenticatedData
    deriving (Show)

{- request flags to pass iterative query.
  * DO (DNSSEC OK) must be 1 for DNSSEC available resolver
    * https://datatracker.ietf.org/doc/html/rfc4035#section-3.2.1
  * CD (Checking Disabled)
  * AD (Authenticated Data)
    * https://datatracker.ietf.org/doc/html/rfc6840#section-5.7
      "setting the AD bit in a query as a signal indicating that the requester understands and is interested in the value of the AD bit in the response" -}
requestDO :: QueryContext -> RequestDO
requestDO QueryContext{..} = case extDO $ qctlEdns qcontrol_ of
    FlagSet -> DnssecOK
    _ -> NoDnssecOK

_requestCD :: QueryContext -> RequestCD
_requestCD QueryContext{..} = case cdBit $ qctlHeader qcontrol_ of
    FlagSet -> CheckDisabled
    _ -> NoCheckDisabled

_requestAD :: QueryContext -> RequestAD
_requestAD QueryContext{..} = case adBit $ qctlHeader qcontrol_ of
    FlagSet -> AuthenticatedData
    _ -> NoAuthenticatedData

---

{-
反復検索の概要

目的のドメインに対して、TLD(トップレベルドメイン) から子ドメインの方向へと順に、権威サーバへの A クエリを繰り返す.
権威サーバへの A クエリの返答メッセージには、
authority セクションに、次の権威サーバ群の名前 (NS) が、
additional セクションにその名前に対するアドレス (A および AAAA) が入っている.
この情報を使って、繰り返し、子ドメインへの検索を行なう.
検索ドメインの初期値はTLD、権威サーバ群の初期値はルートサーバとなる.
 -}

-- | Getting a response corresponding to a query.
--   The cache is maybe updated.
getResponseIterative
    :: Env
    -> DNSMessage
    -> IO (Either String DNSMessage)
getResponseIterative env reqM = case DNS.question reqM of
    [] -> return $ Left "empty question"
    qs@(q : _) -> getResponseIterative' env reqM q qs

getResponseIterative'
    :: Env
    -> DNSMessage
    -> DNS.Question
    -> [DNS.Question]
    -> IO (Either String DNSMessage)
getResponseIterative' env reqM q@(DNS.Question bn typ _) qs = do
    ers <- runDNSQuery getResult env $ QueryContext (ctrlFromRequestHeader reqH reqEH) q
    return $ replyMessage ers (DNS.identifier reqH) qs
  where
    reqH = DNS.header reqM
    reqEH = DNS.ednsHeader reqM
    prefix = "resp-iterative: orig-query " ++ show bn ++ " " ++ show typ ++ ": "
    getResult = logQueryErrors prefix $ do
        guardRequestHeader reqH reqEH
        getResultIterative bn typ

data CacheResult
    = None
    | Positive DNSMessage
    | Negative String

toCacheResult :: Either String DNSMessage -> CacheResult
toCacheResult (Left x) = Negative x
toCacheResult (Right x) = Positive x

-- | Getting a response corresponding to a query from the cache.
getResponseCached
    :: Env
    -> DNSMessage
    -> IO CacheResult
getResponseCached env reqM = case DNS.question reqM of
    [] -> return $ Negative "empty question"
    qs@(q : _) -> getResponseCached' env reqM q qs

getResponseCached' :: Env -> DNSMessage -> DNS.Question -> [DNS.Question] -> IO CacheResult
getResponseCached' env reqM q@(DNS.Question bn typ _) qs = do
    ex <- runDNSQuery getResult env $ QueryContext (ctrlFromRequestHeader reqH reqEH) q
    case ex of
        Right Nothing -> return None
        Right (Just r) -> return $ toCacheResult $ mkResponse $ Right r
        Left l -> return $ toCacheResult $ mkResponse $ Left l
  where
    reqH = DNS.header reqM
    reqEH = DNS.ednsHeader reqM
    prefix = "resp-cached: orig-query " ++ show bn ++ " " ++ show typ ++ ": "
    getResult = logQueryErrors prefix $ do
        guardRequestHeader reqH reqEH
        getResultCached bn typ
    mkResponse ers = replyMessage ers (DNS.identifier reqH) qs

ctrlFromRequestHeader :: DNSHeader -> EDNSheader -> QueryControls
ctrlFromRequestHeader reqH reqEH = DNS.doFlag doOp <> DNS.cdFlag cdOp <> DNS.adFlag adOp
  where
    doOp
        | dnssecOK = FlagSet
        | otherwise = FlagClear
    cdOp
        | dnssecOK, DNS.chkDisable flags = FlagSet {- only check when DNSSEC OK -}
        | otherwise = FlagClear
    adOp
        | dnssecOK, DNS.authenData flags = FlagSet {- only check when DNSSEC OK -}
        | otherwise = FlagClear

    flags = DNS.flags reqH
    dnssecOK = case reqEH of
        DNS.EDNSheader edns | DNS.ednsDnssecOk edns -> True
        _ -> False

guardRequestHeader :: DNSHeader -> EDNSheader -> DNSQuery ()
guardRequestHeader reqH reqEH
    | reqEH == DNS.InvalidEDNS =
        throwE $ InvalidEDNS DNS.InvalidEDNS DNS.defaultResponse
    | not rd = throwE $ HasError DNS.Refused DNS.defaultResponse
    | otherwise = pure ()
  where
    rd = DNS.recDesired $ DNS.flags reqH

-- | Converting 'QueryError' and 'Result' to 'DNSMessage'.
replyMessage
    :: Either QueryError Result
    -> DNS.Identifier
    -> [DNS.Question]
    -> Either String DNSMessage
replyMessage eas ident rqs =
    either queryError (Right . message) eas
  where
    dnsError de = fmap message $ (,,) <$> rcodeDNSError de <*> pure [] <*> pure []
    rcodeDNSError e = case e of
        DNS.RetryLimitExceeded -> Right DNS.ServFail
        DNS.FormatError -> Right DNS.FormatErr
        DNS.ServerFailure -> Right DNS.ServFail
        DNS.NotImplemented -> Right DNS.NotImpl
        DNS.OperationRefused -> Right DNS.ServFail {- like bind9 behavior -}
        DNS.BadOptRecord -> Right DNS.BadVers
        _ -> Left $ "DNSError: " ++ show e

    queryError qe = case qe of
        DnsError e -> dnsError e
        NotResponse{} -> Left "qORr is not response"
        InvalidEDNS{} -> Left "Invalid EDNS"
        HasError rc _m -> Right $ message (rrc, [], [])
          where
            rrc = case rc of
                DNS.Refused -> DNS.ServFail
                _ -> rc

    message (rcode, rrs, auth) =
        res
            { DNS.header =
                h
                    { DNS.identifier = ident
                    , DNS.flags = f{DNS.authAnswer = False, DNS.rcode = rcode}
                    }
            , DNS.answer = rrs
            , DNS.authority = auth
            , DNS.question = rqs
            }
    res = DNS.defaultResponse
    h = DNS.header res
    f = DNS.flags h

-- | Getting a response corresponding to 'Domain' and 'TYPE'.
--   The cache is maybe updated.
getResultIterative :: Domain -> TYPE -> DNSQuery Result
getResultIterative n typ = do
    ((cnrrs, _rn), etm) <- resolve n typ
    reqDO <- lift . lift $ asks requestDO
    let fromRRsets = concatMap $ rrListFromRRset reqDO
        fromMessage (msg, (vans, vauth)) = (DNS.rcode $ DNS.flags $ DNS.header msg, fromRRsets vans, fromRRsets vauth)
    return $ makeResult reqDO cnrrs $ either (resultFromRRS reqDO) fromMessage etm

resultFromRRS :: RequestDO -> ResultRRS -> Result
resultFromRRS reqDO (rcode, cans, cauth) = (rcode, fromRRsets cans, fromRRsets cauth)
  where
    fromRRsets = concatMap $ rrListFromRRset reqDO

-- | Getting a response corresponding to 'Domain' and 'TYPE' from the cache.
getResultCached :: Domain -> TYPE -> DNSQuery (Maybe Result)
getResultCached n typ = do
    ((cnrrs, _rn), e) <- resolveByCache n typ
    reqDO <- lift . lift $ asks requestDO
    return $ either (Just . makeResult reqDO cnrrs . resultFromRRS reqDO) (const Nothing) e

makeResult :: RequestDO -> [RRset] -> Result -> Result
makeResult reqDO cnRRset (rcode, ans, auth) =
    ( rcode
    , denyAnswer reqDO $ concat $ map (rrListFromRRset reqDO) cnRRset ++ [ans]
    , allowAuthority reqDO auth
    )
  where
    denyAnswer DnssecOK rrs = rrs
    denyAnswer NoDnssecOK rrs = foldr takeNODNSSEC [] rrs
      where
        takeNODNSSEC rr@ResourceRecord{..} xs
            | rrtype `elem` dnssecTypes = xs
            | otherwise = rr : xs

    allowAuthority NoDnssecOK = foldr takeSOA []
      where
        takeSOA rr@ResourceRecord{rrtype = SOA} xs = rr : xs
        takeSOA _ xs = xs
    allowAuthority DnssecOK = foldr takeAuth []
      where
        allowTypes = SOA : dnssecTypes
        takeAuth rr@ResourceRecord{..} xs
            | rrtype `elem` allowTypes = rr : xs
            | otherwise = xs

    dnssecTypes = [DNSKEY, DS, RRSIG, NSEC, NSEC3]

resolveByCache
    :: Domain
    -> TYPE
    -> DNSQuery (([RRset], Domain), Either ResultRRS ((), ([RRset], [RRset])))
resolveByCache =
    resolveLogic
        "cache"
        (\_ -> pure ((), ([], [])))
        (\_ _ -> pure ((), Nothing, ([], [])))

rrListFromRRset :: RequestDO -> RRset -> [ResourceRecord]
rrListFromRRset reqDO rs@RRset{..} = case reqDO of
    NoDnssecOK -> rrs
    DnssecOK -> case rrsRDatas of
        [] -> []
        _ : _ -> rrs ++ sigs
  where
    rrs =
        [ ResourceRecord rrsName rrsType rrsClass rrsTTL rd
        | rd <- rrsRDatas
        ]
    sigs =
        [ ResourceRecord rrsName RRSIG rrsClass rrsTTL (DNS.toRData sig)
        | sig <- rrsetGoodSigs rs
        ]
