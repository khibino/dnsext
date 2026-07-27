{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Auth.Algorithm (
    getAnswer,
    DB (..),
    dbRD_SOA,
    dbSOArr,
    fromQuery,
) where

import Data.ByteString.Short ()
import Data.List (nub, partition, sort)
import Data.Maybe (catMaybes, isJust)

import DNS.Auth.DB
import DNS.SEC
import DNS.Types

fromQuery :: DNSMessage -> DNSMessage
fromQuery query =
    query
        { -- Copy identifier
          -- Copy question
          flags = flgs
        , ednsHeader = ednsH
        }
  where
    -- RFC 6891: Sec 6.1.1
    ednsH = case ednsHeader query of
        EDNSheader _ -> EDNSheader defaultEDNS
        _ -> NoEDNS
    flgs =
        DNSFlags
            { isResponse = True
            , authAnswer = True
            , trunCation = False
            , -- RFC 1035 Sec 4.1.1 -- just copy
              recDesired = recDesired $ flags query
            , -- RFC 1034 Sec 4.3.1
              recAvailable = False
            , authenData = False
            , chkDisable = False
            }

-- RFC 8906: Sec 3.1.3.1
--
-- A non-recursive server is supposed to respond to recursive
-- queries as if the Recursion Desired (RD) bit is not set
getAnswer :: DB -> DNSMessage -> DNSMessage
getAnswer db query
    -- RFC 8906: Sec 3.1.4
    | opcode query /= OP_STD = reply{rcode = NotImpl}
    | isResponse (flags query) = reply{rcode = Refused}
    | qtype q `elem` [AXFR, IXFR] = reply{rcode = Refused}
    | not (qname q `isSubDomainOf` dbZone db) =
        reply
            { rcode = Refused
            , flags = (flags reply){authAnswer = False}
            }
    | ednsVerErr = reply{rcode = BadVers}
    -- RFC 8906 Sec3.1.3.1. Recursive Queries
    -- A non-recursive server is supposed to respond to recursive
    -- queries as if the Recursion Desired (RD) bit is not set.
    | otherwise = process db q dnssecOK reply
  where
    q = question query
    reply = fromQuery query
    (ednsVerErr, dnssecOK) = case ednsHeader query of
        EDNSheader eh -> (ednsVersion eh /= 0, ednsDnssecOk eh)
        _ -> (False, False)

----------------------------------------------------------------

--                     RRSIG   NSEC
-- Exist               has     has
-- In-domain NS        not     has
-- In-domain DS        has     has
-- Empty non-terminal  not     not
process :: DB -> Question -> Bool -> DNSMessage -> DNSMessage
process db q@Question{..} dnssecOK reply
    | qtype == NSEC = processNSEC db q dnssecOK reply
    | otherwise = processPositive db q dnssecOK reply

processPositive :: DB -> Question -> Bool -> DNSMessage -> DNSMessage
processPositive db q@Question{..} dnssecOK reply = case lookupDB qname db of
    -- RFC 2308 Sec 2.1 Name Error
    NonEx -> makeNegativeReply db qname reply dnssecOK [] Nothing [] NXDomain
    Deleg rrs _ -> processDelegation db q dnssecOK reply [] rrs False
    Exist rrs mwild -> loopPositive db q dnssecOK reply rrs mwild

loopPositive :: DB -> Question -> Bool -> DNSMessage -> [RRSetSig] -> Maybe Domain -> DNSMessage
loopPositive db q@Question{..} dnssecOK reply rrs mwild
    -- RFC 8482 Sec 4.1
    -- Answer with a Subset of Available RRsets
    | qtype == ANY =
        let ans = cook dnssecOK (take 1) rrs
         in makeReply ans [] []
    | otherwise = case checkCNAME dnssecOK rrs of
        Canon ->
            let ans = cook dnssecOK (filter (\x -> rrsetsigType x == qtype)) rrs
                auth
                    | dnssecOK && not (null ans) && isJust mwild =
                        -- RFC 4035
                        -- Sec 3.1.3.3.  Including NSEC RRs: Wildcard Answer Res
                        lookupN qname db
                    | otherwise = []
                add
                    | qtype `elem` [NS, MX] = findAdditional db dnssecOK ans
                    | otherwise = []
             in makeReply ans auth add
        Alias cdom cc -> processCNAME db q dnssecOK reply cc cdom
        CNErr -> makeErrorReply reply ServFail
  where
    makeReply [] _auth add = makeNegativeReply db qname reply dnssecOK [] mwild add NoErr
    makeReply ans auth add = makePositiveReply reply ans auth add NoErr True

----------------------------------------------------------------

processDelegation :: DB -> Question -> Bool -> DNSMessage -> Answers -> [RRSetSig] -> Bool -> DNSMessage
processDelegation db Question{..} dnssecOK reply cc rrs aa
    | qtype == DS = makePositiveReply reply dss [] [] NoErr True
    | otherwise = do
        let auth
                | not dnssecOK = nss
                -- RFC 4035
                -- Sec 3.1.4.  Including DS RRs in a Response
                | null dss = allrrs ++ lookupN qname db
                | otherwise = allrrs
            add = findAdditional db dnssecOK auth
         in makePositiveReply reply cc auth add NoErr aa
  where
    allrrs = cook dnssecOK id rrs
    (nss, dss) = partition (\r -> rrtype r == NS) allrrs

----------------------------------------------------------------

processNSEC :: DB -> Question -> Bool -> DNSMessage -> DNSMessage
processNSEC db Question{..} dnssecOK reply = case lookupN' qname db of
    [] -> makeNegativeReply db qname reply dnssecOK [] Nothing [] $ rc qname
    nsec -> makePositiveReply reply nsec [] [] NoErr True
  where
    rc name = case lookupDB name db of -- fixme: db is too large?
        NonEx -> NXDomain
        _ -> NoErr

----------------------------------------------------------------

-- RFC 1912 Sec 2.4 CNAME records
-- This function does not follow CNAME of CNAME.
processCNAME :: DB -> Question -> Bool -> DNSMessage -> [ResourceRecord] -> Domain -> DNSMessage
processCNAME db@DB{..} Question{..} dnssecOK reply cc cname
    | qtype == CNAME = makePositiveReply reply cc [] add NoErr True
  where
    add
        | cname `isSubDomainOf` dbZone -- fixme: amp attack?
            =
            cookDo (cook dnssecOK id) $ lookupDB cname db
        | otherwise = []
processCNAME db@DB{..} q@Question{..} dnssecOK reply cc cname
    | cname `isSubDomainOf` dbZone = case lookupDB cname db of
        -- RFC 2308 Sec 2.1 Name Error
        NonEx -> makeNegativeReply db cname reply dnssecOK cc Nothing [] NXDomain
        Deleg rrs _ -> processDelegation db q dnssecOK reply cc rrs True
        Exist rrs _ ->
            let ans = cook dnssecOK (filter (\x -> rrsetsigType x == qtype)) rrs
                -- RFC2308 Sec 2.2 No Data
                auth
                    | null ans = dbSOArr dnssecOK db
                    | otherwise = []
             in makePositiveReply reply (cc ++ ans) auth [] NoErr True
    | otherwise = makePositiveReply reply cc [] [] NoErr True

----------------------------------------------------------------

findAdditional
    :: DB
    -> Bool
    -> [ResourceRecord] -- NSs in Answer or Authority
    -> [ResourceRecord]
findAdditional db@DB{..} dnssecOK rs0 = add
  where
    doms0 = nub $ sort $ catMaybes (map extractNS rs0) ++ catMaybes (map extractMX rs0)
    doms = filter (\d -> d `isSubDomainOf` dbZone) doms0
    add = concat $ map lookupAdd doms
    aORaaaa = filter (\x -> rrsetsigType x `elem` [A, AAAA])
    lookupAdd dom = cookDo (cook dnssecOK aORaaaa) $ lookupDB dom db
    extractNS rr = ns_domain <$> fromRData (rdata rr)
    extractMX rr = mx_exchange <$> fromRData (rdata rr)

----------------------------------------------------------------

cook :: Bool -> ([RRSetSig] -> [RRSetSig]) -> [RRSetSig] -> [ResourceRecord]
cook dnssecOK f rrs = concat $ map (getRRs dnssecOK) $ f rrs

cookDo :: ([RRSetSig] -> [a]) -> Result -> [a]
cookDo f (Deleg _ (Just rrs)) = f rrs
cookDo f (Exist rrs _) = f rrs
cookDo _ _ = []

----------------------------------------------------------------

makePositiveReply :: DNSMessage -> Answers -> AuthorityRecords -> AdditionalRecords -> RCODE -> Bool -> DNSMessage
makePositiveReply reply ans auth add code aa =
    reply
        { answer = ans
        , authority = auth
        , additional = add
        , rcode = code
        , flags = (flags reply){authAnswer = aa}
        }

makeNegativeReply :: DB -> Domain -> DNSMessage -> Bool -> Answers -> Maybe Domain -> AdditionalRecords -> RCODE -> DNSMessage
makeNegativeReply db dom reply dnssecOK ans mwild add code =
    reply
        { answer = ans -- CNAME sometime
        -- wildcard may produce duplicated NSEC RRs
        , authority = auth ++ nub (sort nsec)
        , additional = add
        , rcode = code
        , flags = (flags reply){authAnswer = True}
        }
  where
    auth = dbSOArr dnssecOK db
    nsec
        | not dnssecOK = []
        | otherwise = case mwild of
            Nothing
                | code == NXDomain -> case lookupN dom db of
                    [] -> []
                    -- RFC 4035
                    -- 3.1.3.2.  Including NSEC RRs: Name Error Response
                    -- fixme: how to make the wildcard?
                    xs -> xs ++ lookupN (toWildcard dom) db
                | otherwise ->
                    -- RFC 4035
                    -- 3.1.3.1.  Including NSEC RRs: No Data Response
                    lookupN dom db
            -- RFC 4035
            -- Sec 3.1.3.4.  Including NSEC RRs: Wildcard No Data Response
            Just wild -> lookupN dom db ++ lookupN wild db

makeErrorReply :: DNSMessage -> RCODE -> DNSMessage
makeErrorReply reply code =
    reply
        { answer = []
        , authority = []
        , additional = []
        , rcode = code
        , flags = (flags reply){authAnswer = False}
        }
