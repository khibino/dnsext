{-# LANGUAGE RecordWildCards #-}

module Monitor (
    monitor,
) where

-- GHC packages
import Control.Applicative ((<|>))
import Control.Concurrent (forkFinally, forkIO, threadWaitRead)
import Control.Concurrent.STM (STM, atomically, newTVarIO, readTVar, writeTVar)
import Control.Monad (guard, unless, void, when, (<=<))
import DNS.Types.Decode (EpochTime)
import Data.Char (toUpper)
import Data.Functor (($>))
import Data.List (find, isInfixOf)
import System.IO (
    Handle,
    IOMode (ReadWriteMode),
    hClose,
    hFlush,
    hGetLine,
    hIsEOF,
    hPutStr,
    hPutStrLn,
    stdin,
    stdout,
 )
import Text.Read (readMaybe)

-- dnsext-* packages

import qualified DNS.Do53.Memo as Cache
import qualified DNS.Types as DNS
import Network.Socket (
    AddrInfo (..),
    HostName,
    PortNumber,
    SockAddr,
    Socket,
    SocketType (Stream),
 )
import qualified Network.Socket as S

-- other packages
import UnliftIO (tryAny, waitSTM, withAsync)

-- this package
import DNS.Cache.Iterative (Env (..))
import DNS.Cache.Server
import qualified DNS.Log as Log

import Config
import SocketUtil (addrInfo)

monitorSockets :: PortNumber -> [HostName] -> IO [(Socket, SockAddr)]
monitorSockets port = mapM aiSocket . filter ((== Stream) . addrSocketType) <=< addrInfo port
  where
    aiSocket ai =
        (,)
            <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
            <*> pure (addrAddress ai)

data Command
    = Param
    | Find String
    | Lookup DNS.Domain DNS.TYPE
    | Status
    | Expire EpochTime
    | Noop
    | Exit
    | Quit
    | Help (Maybe String)
    deriving (Show)

monitor
    :: Config
    -> Env
    -> ([PLStatus], IO (Int, Int), IO (Int, Int))
    -> IO ()
    -> IO [IO ()]
monitor conf env getsSizeInfo terminate = do
    let monPort' = fromIntegral $ cnf_monitor_port conf
    ps <- monitorSockets monPort' ["::1", "127.0.0.1"]
    let ss = map fst ps
    sequence_ [S.setSocketOption sock S.ReuseAddr 1 | sock <- ss]
    mapM_ (uncurry S.bind) ps
    sequence_ [S.listen sock 5 | sock <- ss]
    monQuit <- do
        qRef <- newTVarIO False
        return (writeTVar qRef True, readTVar qRef >>= guard)
    when (cnf_monitor_stdio conf) $ runStdConsole monQuit
    return $ map (monitorServer monQuit) ss
  where
    runStdConsole monQuit = do
        let repl =
                console conf env getsSizeInfo terminate monQuit stdin stdout "<std>"
        void $ forkIO repl
    logLn level = logLines_ env level Nothing . (: [])
    handle onError = either onError return <=< tryAny
    monitorServer monQuit@(_, waitQuit) s = do
        let step = do
                socketWaitRead s
                (sock, addr) <- S.accept s
                sockh <- S.socketToHandle sock ReadWriteMode
                let repl =
                        console conf env getsSizeInfo terminate monQuit sockh sockh $
                            show addr
                void $ forkFinally repl (\_ -> hClose sockh)
            loop =
                either (const $ return ()) (const loop)
                    =<< withWait
                        waitQuit
                        (handle (logLn Log.WARN . ("monitor io-error: " ++) . show) step)
        loop

console
    :: Config
    -> Env
    -> ([PLStatus], IO (Int, Int), IO (Int, Int))
    -> IO ()
    -> (STM (), STM ())
    -> Handle
    -> Handle
    -> String
    -> IO ()
console conf env (pQSizeList, ucacheQSize, logQSize) terminate (issueQuit, waitQuit) inH outH ainfo = do
    let input = do
            s <- hGetLine inH
            let err =
                    hPutStrLn
                        outH
                        ("monitor error: " ++ ainfo ++ ": command parse error: " ++ show s)
            maybe (err $> False) runCmd $ parseCmd $ words s

        step = do
            eof <- hIsEOF inH
            if eof then return True else input

        repl = do
            hPutStr outH "monitor> " *> hFlush outH
            either
                (const $ return ())
                (\exit -> unless exit repl)
                =<< withWait waitQuit (handle (($> False) . print) step)

    repl
  where
    handle onError = either onError return <=< tryAny

    parseTYPE s =
        find match types
      where
        us = map toUpper s
        match t = show t == us
        types = map DNS.toTYPE [1 .. 512]

    parseCmd [] = Just Noop
    parseCmd ws = case ws of
        "param" : _ -> Just Param
        "find" : s : _ -> Just $ Find s
        ["lookup", n, typ] -> Lookup (DNS.fromRepresentation n) <$> parseTYPE typ
        "status" : _ -> Just Status
        "expire" : args -> case args of
            [] -> Just $ Expire 0
            x : _ -> Expire <$> readMaybe x
        "exit" : _ -> Just Exit
        "quit-server" : _ -> Just Quit
        "help" : w : _ -> Just $ Help $ Just w
        "help" : [] -> Just $ Help Nothing
        _ -> Nothing

    outLn = hPutStrLn outH

    runCmd Quit = terminate *> atomically issueQuit $> True
    runCmd Exit = return True
    runCmd cmd = dispatch cmd $> False
      where
        dispatch Param = mapM_ outLn $ showConfig conf
        dispatch Noop = return ()
        dispatch (Find s) =
            mapM_ outLn . filter (s `isInfixOf`) . map show . Cache.dump =<< getCache_ env
        dispatch (Lookup dom typ) = maybe (outLn "miss.") hit =<< lookupCache
          where
            lookupCache = do
                cache <- getCache_ env
                ts <- currentSeconds_ env
                return $ Cache.lookup ts dom typ DNS.classIN cache
            hit (rrs, rank) = mapM_ outLn $ ("hit: " ++ show rank) : map show rrs
        dispatch Status = printStatus
        dispatch (Expire offset) = expireCache env . (+ offset) =<< currentSeconds_ env
        dispatch (Help w) = printHelp w
        dispatch x = outLn $ "command: unknown state: " ++ show x

    printStatus = do
        outLn . ("cache size: " ++) . show . Cache.size =<< getCache_ env
        let psize s getSize = do
                (cur, mx) <- getSize
                outLn $ s ++ " size: " ++ show cur ++ " / " ++ show mx
        sequence_
            [ do
                psize ("request queue " ++ index) reqQSize
                psize ("decoded queue " ++ index) decQSize
                psize ("response queue " ++ index) resQSize
            | (i, workerStatusList) <- zip [0 :: Int ..] pQSizeList
            , (j, WorkerStatus{..}) <-
                zip [0 :: Int ..] workerStatusList
            , let index = show i ++ "," ++ show j
            ]
        psize "ucache queue" ucacheQSize
        lmx <- snd <$> logQSize
        when (lmx >= 0) $ psize "log queue" logQSize

        ts <-
            sequence
                [ (,,) <$> getHit <*> getMiss <*> getFailed
                | workerStatusList <- pQSizeList
                , WorkerStatus{..} <- workerStatusList
                ]
        let hits = sum [hit | (hit, _, _) <- ts]
            replies = hits + sum [miss | (_, miss, _) <- ts]
            total = replies + sum [failed | (_, _, failed) <- ts]
        outLn $ "hit rate: " ++ show hits ++ " / " ++ show replies
        outLn $ "reply rate: " ++ show replies ++ " / " ++ show total

    printHelp mw = case mw of
        Nothing -> hPutStr outH $ unlines [showHelp h | (_, h) <- helps]
        Just w ->
            maybe (outLn $ "unknown command: " ++ w) (outLn . showHelp) $ lookup w helps
      where
        showHelp (syn, msg) = syn ++ replicate (width - length syn) ' ' ++ " - " ++ msg
        width = 20
        helps =
            [ ("param", ("param", "show server parameters"))
            , ("find", ("find STRING", "find sub-string from dumped cache"))
            , ("lookup", ("lookup DOMAIN TYPE", "lookup cache"))
            , ("status", ("status", "show current server status"))
            ,
                ( "expire"
                , ("expire [SECONDS]", "expire cache at the time SECONDS later")
                )
            , ("exit", ("exit", "exit this management session"))
            , ("quit-server", ("quit-server", "quit this server"))
            , ("help", ("help", "show this help"))
            ]

withWait :: STM a -> IO b -> IO (Either a b)
withWait qstm blockAct =
    withAsync blockAct $ \a ->
        atomically $
            (Left <$> qstm)
                <|> (Right <$> waitSTM a)

socketWaitRead :: Socket -> IO ()
socketWaitRead sock = S.withFdSocket sock $ threadWaitRead . fromIntegral