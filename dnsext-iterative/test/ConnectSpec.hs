module ConnectSpec where

import Control.Exception (bracket)
import Data.Functor
import Network.Socket (AddrInfo (..), AddrInfoFlag (..), SocketType (..))
import qualified Network.Socket as S
-- import System.IO.Error (tryIOError)

import Test.Hspec

{- FOURMOLU_DISABLE -}
spec :: Spec
spec = describe "connect" $ do
    it "Nothing" $ checkV6  Nothing
    it "Just 0"  $ checkV6 (Just "0")
    it "Just 53" $ checkV6 (Just "53")
  where
    datagramAI6 an srv = S.getAddrInfo (Just S.defaultHints{addrFlags = [AI_ADDRCONFIG], addrSocketType = Datagram}) (Just an) srv
    checkRoute (sa:_) (AddrInfo{addrAddress = peer}:_)  = (bracket (S.openSocket sa) S.close $ \s -> S.connect s peer) $> True
    checkRoute  _      _                                = pure False
    checkV6 rsrv = do
        local   <- datagramAI6 "::"                  Nothing
        remote  <- datagramAI6 "2001:503:ba3e::2:30" rsrv
        putStrLn $ "local :" ++ show (take 1 local)
        putStrLn $ "remote:" ++ show (take 1 remote)
        rv <- checkRoute local remote
        rv `shouldBe` True
{- FOURMOLU_ENABLE -}
