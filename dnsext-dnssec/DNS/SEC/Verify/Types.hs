{-# LANGUAGE ExistentialQuantification #-}

module DNS.SEC.Verify.Types where

-- dnsext-types
import DNS.Types

-- this package
import DNS.SEC.Imports
import DNS.SEC.PubKey
import DNS.SEC.Types (RD_NSEC3)

data RRSIGImpl =
  forall pubkey sig .
  RRSIGImpl
  { rrsigIGetKey :: PubKey -> Either String pubkey
  , rrsigIGetSig :: Opaque -> Either String sig
  , rrsigIVerify :: pubkey -> sig -> ByteString -> Either String Bool
  }

data DSImpl =
  forall digest .
  DSImpl
  { dsIGetDigest :: ByteString -> digest
  , dsIVerify :: digest -> ByteString -> Bool
  }

data NSEC3Impl =
  forall hash .
  NSEC3Impl
  { nsec3IGetHash :: ByteString -> hash
  , nsec3IGetBytes :: hash -> ByteString
  }

{- | owner name and NSEC3 rdata express hashed domain-name range -}
type NSEC3_Range = (Domain, RD_NSEC3)

{- | range and qname which is owner of it or covered by it -}
type NSEC3_Witness = (NSEC3_Range, Domain)

{- | verify result of NSEC3 -}
data NSEC3_Result
  = N3Result_NameError
    { nsec3_closest_match     :: NSEC3_Witness
    , nsec3_next_closer_cover :: NSEC3_Witness
    , nsec3_wildcard_cover    :: NSEC3_Witness
    }
    {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.1 -}
  | N3Result_NoData
    { nsec3_closest_match     :: NSEC3_Witness }
    {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.2
       https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.6 -}
  | N3Result_OptOutDelegation
    { nsec3_closest_match     :: NSEC3_Witness
    , nsec3_next_closer_cover :: NSEC3_Witness
    }
    {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.3 -}
  | N3Result_WildcardExpansion
    { nsec3_next_closer_cover :: NSEC3_Witness }
    {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.4 -}
  | N3Result_WildcardNoData
    { nsec3_closest_match     :: NSEC3_Witness
    , nsec3_next_closer_cover :: NSEC3_Witness
    , nsec3_wildcard_match    :: NSEC3_Witness
    }
    {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.5 -}
  deriving Show
