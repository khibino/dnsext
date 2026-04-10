{-# LANGUAGE RecordWildCards #-}

module Auth (server, tcpAllowAXFR) where

import Data.ByteString (ByteString)
import Data.IP
import Network.Socket

import DNS.Auth.Algorithm
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode
import Data.IORef

import Axfr
import Types
import Zone

server :: Env -> Proto -> ZoneAlist -> IO ()
server env proto@Proto{..} zoneAlist = loop
  where
    loop = do
        (bs, sa) <- recvQuery
        case decode bs of
            -- fixme: which RFC?
            Left _e -> return ()
            Right query -> case opcode query of
                OP_NOTIFY -> handleNotify proto zoneAlist sa query
                OP_STD -> do
                    let q = question query
                        dom = qname q
                        typ = qtype q
                    case typ of
                        AXFR -> do
                            mx <- allowAXFR sa dom zoneAlist
                            case mx of
                                Nothing -> sendReply sa $ replyRefused query
                                Just zone -> transfer env proto zone sa query
                        IXFR -> undefined
                        _ -> response proto zoneAlist sa query dom
                _ -> sendReply sa $ replyRefused query
        loop

response :: Proto -> ZoneAlist -> SockAddr -> DNSMessage -> Domain -> IO ()
response Proto{..} zoneAlist sa query dom = case findZoneAlist dom zoneAlist of -- isSubDomainOf
    Nothing -> sendReply sa $ replyRefused query
    Just (_, zoneref) -> do
        zone <- readIORef zoneref
        sendReply sa $ replyQuery query $ zoneDB zone

handleNotify :: Proto -> ZoneAlist -> SockAddr -> DNSMessage -> IO ()
handleNotify Proto{..} zoneAlist sa query = case lookup dom zoneAlist of -- exact match
    Nothing -> sendReply sa $ replyRefused query
    Just zoneref -> do
        Zone{..} <- readIORef zoneref
        case fromSockAddr sa of
            Nothing -> sendReply sa $ replyRefused query
            Just (ip, _)
                | ip `elem` zoneAllowNotifyAddrs -> do
                    sendReply sa $ replyNotice query
                    zoneWakeUp
                | otherwise -> sendReply sa $ replyRefused query
  where
    dom = qname $ question query

replyNotice :: DNSMessage -> ByteString
replyNotice query = encode $ fromQuery query

replyQuery :: DNSMessage -> DB -> ByteString
replyQuery query db = encode $ getAnswer db query

replyRefused :: DNSMessage -> ByteString
replyRefused query = encode $ (fromQuery query){rcode = Refused}
