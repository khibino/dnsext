{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Monad (when)
import DNS.Do53.Client (FlagOp (..), QueryControls, doFlag, rdFlag)
import DNS.Do53.Internal (Reply (..), Result (..))
import DNS.DoX.Stub
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (ALPN, addResourceDataForSVCB)
import DNS.Types (TYPE (..), runInitIO)
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.List (intercalate, isPrefixOf)
import qualified Data.UnixTime as T
import Network.Socket (PortNumber)
import System.Console.ANSI (setSGR)
import System.Console.ANSI.Types
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import Text.Read (readMaybe)

import DNS.Cache.Iterative (
    IterativeControls (..),
    RequestAD (..),
    RequestCD (..),
    RequestDO (..),
    defaultIterativeControls,
    setRequestAD,
    setRequestCD,
    setRequestDO,
 )
import qualified DNS.Log as Log

import Iterative (iterativeQuery)
import Output (pprResult)
import Recursive (recursiveQeury)

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['h']
        ["help"]
        (NoArg (\opts -> opts{optHelp = True}))
        "print help"
    , Option
        ['i']
        ["iterative"]
        (NoArg (\opts -> opts{optIterative = True}))
        "resolve iteratively"
    , Option
        ['4']
        ["ipv4"]
        (NoArg (\opts -> opts{optDisableV6NS = True}))
        "disable IPv6 NS"
    , Option
        ['p']
        ["port"]
        (ReqArg (\port opts -> opts{optPort = Just port}) "<port>")
        "specify port number"
    , Option
        ['d']
        ["dox"]
        ( ReqArg
            (\dox opts -> opts{optDoX = Short.toShort (C8.pack dox)})
            "auto|dot|doq|h2|h3"
        )
        "enable DoX"
    , Option
        []
        ["debug"]
        (NoArg (\opts -> opts{optLogLevel = Log.DEBUG}))
        "set the log level to DEBUG"
    , Option
        []
        ["warn"]
        (NoArg (\opts -> opts{optLogLevel = Log.WARN}))
        "set the log level to WARN"
    , Option
        []
        ["demo"]
        (NoArg (\opts -> opts{optLogLevel = Log.DEMO}))
        "set the log level to DEMO"
    ]

data Options = Options
    { optHelp :: Bool
    , optIterative :: Bool
    , optDisableV6NS :: Bool
    , optPort :: Maybe String
    , optDoX :: ShortByteString
    , optLogLevel :: Log.Level
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optHelp = False
        , optIterative = False
        , optDisableV6NS = False
        , optPort = Nothing
        , optDoX = "do53"
        , optLogLevel = Log.WARN
        }

main :: IO ()
main = do
    (args, Options{..}) <- getArgs >>= getArgsOpts
    when optHelp $ do
        putStr $ usageInfo help options
        exitSuccess
    let (at, plus, targets) = divide args
    (dom, typ) <- getDomTyp targets
    port <- getPort optPort optDoX
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    ----
    t0 <- T.getUnixTime
    msg <-
        if optIterative
            then do
                let ictl = mkIctrl plus
                ex <- iterativeQuery optDisableV6NS Log.Stdout optLogLevel ictl dom typ
                case ex of
                    Left e -> fail e
                    Right msg -> do
                        setSGR [SetColor Foreground Vivid Green]
                        putStr ";; "
                        return msg
            else do
                let mserver = map (drop 1) at
                    ctl = mconcat $ map toFlag plus
                ex <- recursiveQeury mserver port optDoX dom typ ctl
                case ex of
                    Left e -> fail $ show e
                    Right Result{..} -> do
                        let Reply{..} = resultReply
                        setSGR [SetColor Foreground Vivid Green]
                        putStr $
                            ";; " ++ resultHostName ++ "#" ++ show resultPortNumber ++ "/" ++ resultTag
                        putStr $ ", Tx:" ++ show replyTxBytes ++ "bytes"
                        putStr $ ", Rx:" ++ show replyRxBytes ++ "bytes"
                        putStr ", "
                        return $ replyDNSMessage
    t1 <- T.getUnixTime
    let T.UnixDiffTime s u = (t1 `T.diffUnixTime` t0)
    when (s /= 0) $ putStr $ show s ++ "sec "
    putStr $ show (u `div` 1000) ++ "usec"
    putStr "\n\n"
    setSGR [Reset]
    putStr $ pprResult msg

----------------------------------------------------------------

divide :: [String] -> ([String], [String], [String])
divide ls = loop ls (id, id, id)
  where
    loop [] (b0, b1, b2) = (b0 [], b1 [], b2 [])
    loop (x : xs) (b0, b1, b2)
        | "@" `isPrefixOf` x = loop xs (b0 . (x :), b1, b2)
        | "+" `isPrefixOf` x = loop xs (b0, b1 . (x :), b2)
        | otherwise = loop xs (b0, b1, b2 . (x :))

----------------------------------------------------------------

getArgsOpts :: [String] -> IO ([String], Options)
getArgsOpts args = case getOpt Permute options args of
    (o, n, []) -> return (n, foldl (flip id) defaultOptions o)
    (_, _, errs) -> do
        mapM_ putStr errs
        exitFailure

getDomTyp :: [String] -> IO (String, TYPE)
getDomTyp [h] = return (h, A)
getDomTyp [h, t] = do
    let mtyp' = readMaybe t
    case mtyp' of
        Just typ' -> return (h, typ')
        Nothing -> do
            putStrLn $ "Type " ++ t ++ " is not supported"
            exitFailure
getDomTyp _ = do
    putStrLn "One or two arguments are necessary"
    exitFailure

getPort :: Maybe String -> ALPN -> IO PortNumber
getPort Nothing optDoX = return $ doxPort optDoX
getPort (Just x) _ = case readMaybe x of
    Just p -> return p
    Nothing -> do
        putStrLn $ "Port " ++ x ++ " is illegal"
        exitFailure

----------------------------------------------------------------

toFlag :: String -> QueryControls
toFlag "+rec" = rdFlag FlagSet
toFlag "+recurse" = rdFlag FlagSet
toFlag "+norec" = rdFlag FlagClear
toFlag "+norecurse" = rdFlag FlagClear
toFlag "+dnssec" = doFlag FlagSet
toFlag "+nodnssec" = doFlag FlagClear
toFlag _ = mempty -- fixme

----------------------------------------------------------------

mkIctrl :: Foldable t => t String -> IterativeControls
mkIctrl plus = flagAD . flagCD . flagDO $ defaultIterativeControls
  where
    ustep tbl f s = maybe f id $ lookup s tbl
    uflag tbl d = foldl (ustep tbl) d plus
    update get set tbl s = set (uflag tbl $ get s) s
    flagDO = update requestDO setRequestDO tblFlagDO
    flagCD = update requestCD setRequestCD tblFlagCD
    flagAD = update requestAD setRequestAD tblFlagAD

tblFlagDO :: [(String, RequestDO)]
tblFlagDO = [("+dnssec", DnssecOK), ("+nodnssec", NoDnssecOK)]

tblFlagCD :: [(String, RequestCD)]
tblFlagCD = [("+cdflag", CheckDisabled), ("+nocdflag", NoCheckDisabled)]

tblFlagAD :: [(String, RequestAD)]
tblFlagAD = [("+adflag", AuthenticatedData), ("+noadflag", NoAuthenticatedData)]

----------------------------------------------------------------

help :: String
help =
    intercalate
        "\n"
        [ "Usage: dug [@server] [name [query-type [query-option]]] [options]"
        , ""
        , "query-type: a | aaaa | ns | txt | ptr | ..."
        , ""
        , "query-option:"
        , "  +[no]rec[urse]  (Recursive mode)"
        , "  +[no]dnssec     (DNSSEC)"
        , ""
        , "options:"
        ]
