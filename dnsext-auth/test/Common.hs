module Common where

import DNS.SEC
import DNS.Types

include :: Domain -> TYPE -> [ResourceRecord] -> Bool
include dom typ rs = any has rs
  where
    has r = rrname r == dom && rrtype r == typ

includeNS :: Domain -> Domain -> [ResourceRecord] -> Bool
includeNS dom ref rs = any has rs
  where
    has r =
        rrname r == dom && case fromRData $ rdata r of
            Nothing -> False
            Just rd -> ns_domain rd == ref

includeRRSIG :: Domain -> TYPE -> [ResourceRecord] -> Bool
includeRRSIG dom typ rs = any has rs
  where
    has r =
        rrname r == dom && rrtype r == RRSIG && case fromRData $ rdata r of
            Nothing -> False
            Just rd -> rrsig_type rd == typ

dnssecQuery :: DNSMessage
dnssecQuery =
    defaultQuery
        { ednsHeader = EDNSheader defaultEDNS{ednsDnssecOk = True}
        }
