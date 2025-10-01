
import Control.Monad
import Data.List.NonEmpty

import Network.Socket

import LinuxCap
import qualified LinuxCap as Cap

{-
queryNetBind :: CapFlag -> Cap -> IO Bool
queryNetBind cflag cap = do
    flag <- Cap.getFlag cap CAP_NET_BIND_SERVICE cflag
    putStrLn $ "cap_net_bind_service:" ++ show cflag ++ ": " ++ show flag
    pure flag
 -}

setupSocket :: IO (SockAddr, Socket)
setupSocket = do
    let customHint = defaultHints{addrFlags = [AI_ADDRCONFIG], addrSocketType = Stream}
    ai:|_ <- getAddrInfo (Just customHint) (Just "127.0.0.1") (Just "953")
    (,) (addrAddress ai) <$> openSocket ai

printCap :: String -> IO ()
printCap tag = do
    let format ct = putStrLn $ tag ++ ": " ++ ct
    withCurrentCap $ \cap -> withCapText cap format

run :: IO ()
run = do
    printCap "before enable"
    rv <- Cap.setupEffective putStrLn CAP_NET_BIND_SERVICE
    unless rv $ putStrLn "setup-effective: failed"
    printCap " after enable"
    (addr, sock) <- setupSocket
    bind sock addr
    putStrLn $ "bind success: " ++ show sock ++ " " ++ show addr

main :: IO ()
main = run
