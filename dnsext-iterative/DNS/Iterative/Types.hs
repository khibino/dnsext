module DNS.Iterative.Types where

data DoX
    = UDP
    | TCP
    | DoT
    | H2
    | H2C
    | H3
    | DoQ
    deriving (Eq, Show)
