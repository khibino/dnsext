module DNS.Transport.Types where

data DoX
    = UDP
    | TCP
    | DoT
    | H2
    | H2C
    | H3
    | DoQ
    deriving (Eq, Show)

data Synthesis
    = SynthNone
    | SynthDNS64
    deriving (Eq, Show)
