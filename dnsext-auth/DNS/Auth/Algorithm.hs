{-# LANGUAGE RecordWildCards #-}

module DNS.Auth.Algorithm (
    getAnswer,
    DB (..),
    dbRD_SOA,
    dbSOArr,
    fromQuery,
) where

import Data.List (nub, partition, sort)
import qualified Data.Map as M
import Data.Maybe (catMaybes)

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

unwrap :: Bool -> RRSetSig -> [ResourceRecord]
unwrap False RRSetSig{..} = rrsetsigRRs
unwrap True RRSetSig{..} = rrsetsigRRs ++ maybe [] pure rrsetsigSig

-- dbAnswer contains empty ODBs for For RFC 4592 Sec 2.2.2.Empty
-- Non-terminals.
--                     RRSIG   NSEC
-- Exist               has     has
-- In-domain NS        not     has
-- In-domain DS        has     has
-- Empty non-terminal  not     not
process :: DB -> Question -> Bool -> DNSMessage -> DNSMessage
process db@DB{..} q@Question{..} dnssecOK reply
    | qtype == NSEC = processNSEC db q dnssecOK reply
    | qtype == DS = processPositive db dbAuthority q dnssecOK reply
    | otherwise = processPositive db dbAnswer q dnssecOK reply

processPositive :: DB -> ODB -> Question -> Bool -> DNSMessage -> DNSMessage
processPositive db odb q@Question{..} dnssecOK reply = case lookupD qname odb of
    Nothing -> findAuthority db q dnssecOK reply
    Just idb
        -- RFC 8482 Sec 4.1
        -- Answer with a Subset of Available RRsets
        | qtype == ANY ->
            let ans = headIDB dnssecOK idb
             in if null ans
                    then makeNegativeReply db qname reply dnssecOK [] [] NoErr
                    else makePositiveReply reply ans [] [] NoErr True
        | otherwise -> case lookupT CNAME idb of
            Nothing ->
                let ans = maybe [] (unwrap dnssecOK) $ lookupT qtype idb
                    add = if qtype `elem` [NS, MX] then findAdditional db dnssecOK ans else []
                 in if null ans
                        then makeNegativeReply db qname reply dnssecOK [] add NoErr
                        else makePositiveReply reply ans [] add NoErr True
            Just ent -> case rrsetsigRRs ent of
                [c] -> case fromRData $ rdata c of
                    Nothing -> makeErrorReply reply ServFail
                    Just cname ->
                        let cc = case rrsetsigSig ent of
                                Nothing -> [c]
                                Just sig -> [c, sig]
                         in processCNAME db q dnssecOK reply cc $ cname_domain cname
                _ -> makeErrorReply reply ServFail

processNSEC :: DB -> Question -> Bool -> DNSMessage -> DNSMessage
processNSEC db@DB{..} Question{..} dnssecOK reply = case M.lookup key dbNsecMap of
    Nothing -> makeNegativeReply db qname reply dnssecOK [] [] $ rc qname
    Just nsec
        | rrsetsigName nsec == qname ->
            let ans = getRRs dnssecOK nsec
             in makePositiveReply reply ans [] [] NoErr True
        | otherwise -> makeNegativeReply db qname reply dnssecOK [] [] $ rc qname
  where
    key = Exact $ qname
    rc name = case lookupD name dbAnswer of
        Nothing -> NXDomain
        _ -> NoErr

-- RFC 1912 Sec 2.4 CNAME records
-- This function does not follow CNAME of CNAME.
processCNAME :: DB -> Question -> Bool -> DNSMessage -> [ResourceRecord] -> Domain -> DNSMessage
processCNAME DB{..} Question{..} dnssecOK reply cc cname
    | qtype == CNAME = makePositiveReply reply cc [] add NoErr True
  where
    add
        | cname `isSubDomainOf` dbZone =
            maybe [] (allRRsofIDB dnssecOK) $ lookupD cname dbAdditional
        | otherwise = []
processCNAME db@DB{..} Question{..} dnssecOK reply cc cname
    | cname `isSubDomainOf` dbZone = case lookupD cname dbAnswer of
        -- RFC 2308 Sec 2.1 Name Error
        Nothing -> makeNegativeReply db cname reply dnssecOK cc [] NXDomain
        Just idb ->
            let ans = maybe [] (unwrap dnssecOK) $ lookupT qtype idb
                -- RFC2308 Sec 2.2 No Data
                auth
                    | null ans = dbSOArr dnssecOK db
                    | otherwise = []
             in makePositiveReply reply (cc ++ ans) auth [] NoErr True
    | otherwise = makePositiveReply reply cc [] [] NoErr True

findAuthority
    :: DB
    -> Question
    -> Bool
    -> DNSMessage
    -> DNSMessage
findAuthority db@DB{..} Question{..} dnssecOK reply = loop qname
  where
    loop dom
        | dom == dbZone = makeNegativeReply db qname reply dnssecOK [] [] NXDomain
        | otherwise = case unconsDomain dom of
            Nothing -> makeNegativeReply db qname reply dnssecOK [] [] NXDomain
            Just (_, dom') -> case lookupD dom dbAuthority of
                Nothing -> loop dom'
                Just idb
                    -- For RFC 4592 Sec 2.2.2.Empty Non-terminals
                    | null (allRRsofIDB False idb) ->
                        makePositiveReply reply [] (dbSOArr dnssecOK db) [] NoErr True -- fixme
                    | otherwise ->
                        let allrrs = allRRsofIDB dnssecOK idb
                            (nss, dss) = partition (\r -> rrtype r == NS) allrrs
                            auth
                                | dnssecOK && null dss = case M.lookup (Exact qname) dbNsecMap of
                                    Nothing -> allrrs
                                    Just n -> allrrs ++ getRRs dnssecOK n
                                | dnssecOK = allrrs
                                | otherwise = nss
                            add = findAdditional db dnssecOK auth
                         in makePositiveReply reply [] auth add NoErr False

findAdditional
    :: DB
    -> Bool
    -> [ResourceRecord] -- NSs in Answer or Authority
    -> [ResourceRecord]
findAdditional DB{..} dnssecOK rs0 = add
  where
    doms0 = nub $ sort $ catMaybes (map extractNS rs0) ++ catMaybes (map extractMX rs0)
    doms = filter (\d -> d `isSubDomainOf` dbZone) doms0
    add = concat $ map lookupAdd doms
    lookupAdd dom = maybe [] (allRRsofIDB dnssecOK) $ lookupD dom dbAdditional
    extractNS rr = ns_domain <$> fromRData (rdata rr)
    extractMX rr = mx_exchange <$> fromRData (rdata rr)

makePositiveReply :: DNSMessage -> Answers -> AuthorityRecords -> AdditionalRecords -> RCODE -> Bool -> DNSMessage
makePositiveReply reply ans auth add code aa =
    reply
        { answer = ans
        , authority = auth
        , additional = add
        , rcode = code
        , flags = (flags reply){authAnswer = aa}
        }

makeNegativeReply :: DB -> Domain -> DNSMessage -> Bool -> Answers -> AdditionalRecords -> RCODE -> DNSMessage
makeNegativeReply db dom reply dnssecOK ans add code =
    reply
        { answer = ans -- CNAME sometime
        , authority = auth ++ nsec
        , additional = add
        , rcode = code
        , flags = (flags reply){authAnswer = True}
        }
  where
    key = Exact dom
    auth = dbSOArr dnssecOK db
    nsec
        | dnssecOK = case M.lookup key $ dbNsecMap db of
            Nothing -> []
            Just n -> getRRs dnssecOK n
        | otherwise = []

makeErrorReply :: DNSMessage -> RCODE -> DNSMessage
makeErrorReply reply code =
    reply
        { answer = []
        , authority = []
        , additional = []
        , rcode = code
        , flags = (flags reply){authAnswer = False}
        }
