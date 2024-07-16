{-# LANGUAGE NumericUnderscores #-}

-- ghc
-- import Control.Concurrent
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (ShortByteString, toShort)
import Data.String
import System.Environment (getArgs)

-- other
import Data.IP (IP)
import Network.Socket (PortNumber)

-- dnsext-*
import DNS.Do53.Internal (
    ResolveInfo (..),
    defaultResolveInfo,
 )
import DNS.DoX.Client
import DNS.Types (Question (..), CLASS (IN))


toShort' :: String -> ShortByteString
toShort' = toShort . C8.pack

-- ractions = defaultResolveActions

mkResolvInfo :: IP -> PortNumber -> ResolveInfo
mkResolvInfo ip port =
    defaultResolveInfo
    { rinfoIP = ip
    , rinfoPort = port
    , rinfoUDPRetry = 2
    -- , rinfoActions = ractions
    , rinfoVCLimit = 8192
    }

type DoX = (String, IP, PortNumber)

run :: DoX -> [Question] -> IO ()
run (optDoX, ip, port) qs = do
    let optDoX' = toShort' optDoX
    presolver <- maybe (fail $ "run: unknown mode: " ++ optDoX) pure $ makePersistentResolver optDoX'
    let body resolv q = do
            _ <- getLine
            print =<< resolv q mempty
    presolver (mkResolvInfo ip port) $ \resolv -> mapM_ (body resolv) qs
    pure ()

doxList :: [(String, DoX)]
doxList =
    [ (n, t)
    | t@(n, _, _) <-
      [ ("tcp", fromString "127.0.0.1", 1053)
      , ("dot", fromString "127.0.0.1", 1853)
      , ("h2", fromString "127.0.0.1", 1443)
      , ("h2c", fromString "127.0.0.1", 1080)
      , ("doq", fromString "127.0.0.1", 1853)
      ]
    ]

getDoX :: String -> IO DoX
getDoX x = maybe (fail $ "unkown mode: " ++ x) pure $ lookup x doxList

getQuestions :: [String] -> IO [Question]
getQuestions = go id
  where
    go a []        = pure $ a []
    go _ [x]       = fail $ "getQuestions: " ++ show x
    go a (n:t:xs)  = do
        ty <- readIO t
        go (a . (Question (fromString n) ty IN :)) xs

main :: IO ()
main = do
    args <- getArgs
    (dox, qs)  <- case args of
        []    -> fail "Usage: iquery {tcp|dot|doq} [DOMAIN TYPE].. "
        x:qs  -> (,) <$> getDoX x <*> getQuestions qs
    print dox
    run dox qs
