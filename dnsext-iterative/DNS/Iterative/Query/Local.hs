module DNS.Iterative.Query.Local where

-- GHC packages
import qualified Data.Map.Strict as Map

-- dnsext-types
import DNS.Types

-- dnsext-utils
import DNS.Transport.Types (Synthesis (..))

-- this package

import DNS.Iterative.Query.Class
import DNS.Iterative.Query.LocalZone (lookupApex, lookupName)
import DNS.Iterative.Query.StubZone (lookupStub)

type TakeLocal a = Env -> Question -> a -> a -> (ResultRRS -> a) -> a

{- FOURMOLU_DISABLE -}
takeLocalResult :: Env -> Question -> a -> a -> (ResultRRS -> a) -> a
takeLocalResult env q@Question{qname=dom,qclass=cls} denied nothing just
    | IN <- cls, Just{} <- lookupStub (stubZones_ env) dom                              = nothing  {- stubs supersede locals -}
    | CH <- cls, (apexes, names) <- chaosZones_ env, Just apex <- lookupApex apexes dom = maybe denied just $ lookupName names apex q
    | IN <- cls, (apexes, names) <- localZones_ env, Just apex <- lookupApex apexes dom = maybe denied just $ lookupName names apex q
    | otherwise                                                                         = nothing
{- FOURMOLU_ENABLE -}

takeLocalSynthNone :: Env -> Question -> a -> a -> (ResultRRS -> a) -> a
takeLocalSynthNone = takeLocalSynthZone SynthNone

takeLocalSynthDNS64 :: Env -> Question -> a -> a -> (ResultRRS -> a) -> a
takeLocalSynthDNS64 = takeLocalSynthZone SynthDNS64

{- FOURMOLU_DISABLE -}
takeLocalSynthZone :: Synthesis -> Env -> Question -> a -> a -> (ResultRRS -> a) -> a
takeLocalSynthZone synth env q@Question{qname=dom,qclass=cls} denied nothing just
    | IN <- cls, Just{} <- lookupStub (stubZones_ env) dom                              = nothing  {- stubs supersede locals -}
    | IN <- cls, Just (apexes, names) <- synthZones, Just apex <- lookupApex apexes dom = maybe denied just $ lookupName names apex q
    | otherwise                                                                         = nothing
  where
    synthZones = Map.lookup synth (localSynthZones_ env)
{- FOURMOLU_ENABLE -}

takeLocalNoop :: Env -> Question -> a -> a -> (ResultRRS -> a) -> a
takeLocalNoop _env _q _denied nothing _just = nothing
