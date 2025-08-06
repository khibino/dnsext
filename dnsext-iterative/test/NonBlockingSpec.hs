
module NonBlockingSpec where

-- GHC packages
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Functor
import Data.IORef
import Data.String

-- packages for tests
import Test.Hspec (Spec, describe, hspec, it, shouldReturn)
import Test.Hspec.Expectations.Contrib (annotate)

-- this packages
import DNS.Iterative.Server

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
    specFromChunks
    specReadable
    specCtlRecvVC

---

{- FOURMOLU_DISABLE -}
-- test cases, read results from readable chunks
specFromChunks :: Spec
specFromChunks = do
    describe "controlledRecv from chunks" $ do
        it "chuncked read" $ do
            testNBRecvN "" [] 5 [eof, eof, eof]
            testNBRecvN "" ["abcde"] 5 [nbytes "abcde", eof]
            testNBRecvN
                ""
                ["abcdefgh"]
                5
                [nbytes "abcde", NotEnough, eof]

            testNBRecvN
                ""
                ["ab", "cdefgh"]
                5
                [NotEnough, nbytes "abcde", NotEnough, eof]
            testNBRecvN
                ""
                ["a", "b", "c", "d", "e", "f", "g", "h"]
                5
                [ NotEnough
                , NotEnough
                , NotEnough
                , NotEnough
                , nbytes "abcde"
                , NotEnough
                , NotEnough
                , NotEnough
                , eof
                , eof
                ]

            testNBRecvN "xyz" [] 2 [nbytes "xy", NotEnough, eof, eof]
            testNBRecvN "xyz" [] 5 [NotEnough, eof, eof]
            testNBRecvN "xyz" ["ab"] 5 [nbytes "xyzab", eof, eof]
            testNBRecvN
                "xyz"
                ["abcdefgh"]
                5
                [nbytes "xyzab", nbytes "cdefg", NotEnough, eof]

            testNBRecvN
                "xyz"
                ["ab", "cdefgh"]
                5
                [nbytes "xyzab", nbytes "cdefg", NotEnough, eof]
            testNBRecvN
                "xyz"
                ["a", "b", "c", "d", "e", "f", "g", "h"]
                5
                [ NotEnough
                , nbytes "xyzab"
                , NotEnough
                , NotEnough
                , NotEnough
                , NotEnough
                , nbytes "cdefg"
                , NotEnough
                , eof
                , eof
                ]
{- FOURMOLU_ENABLE -}

-- old name for checking from-chunks cases
testNBRecvN
    :: String -> [String] -> Int -> [Result] -> IO ()
testNBRecvN = testFromChunks

{- FOURMOLU_DISABLE -}
testFromChunks
    :: String -> [String] -> Int -> [Result] -> IO ()
testFromChunks ini xxs n ress = do
    rcv      <- mockFromChunks [fromString x | x <- prepend ini xxs]
    ctlRecv  <- controlledRecv <$> newControl (return False) <*> pure rcv
    sequence_ [annotate (show (ini, xxs, n)) $ ctlRecv n `shouldReturn` res | res <- ress]
  where
    prepend i  [] | i == mempty  = []
                  | otherwise    = [i]
    prepend i (x:xs)             = i <> x : xs
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
-- test cases, readable state with events
specReadable :: Spec
specReadable = do
    describe "controlledRecv readable" $ do
        it "eof" $ do
            testNBRecvNReadable
                [ (Close, True, [ (3, eof, False) ])
                ]
        it "not-enough" $ do
            testNBRecvNReadable
                [ (Bytes "abc", True, [ (5, NotEnough, False) ])
                , (Close      , True, [])
                ]
        it "n-bytes - just" $ do
            testNBRecvNReadable
                [ (Bytes "abc", True, [ (3, nbytes "abc", False) ])
                , (Close      , True, [ (3, eof         , False) ])
                ]
        it "n-bytes - over" $ do
            testNBRecvNReadable
                [ (Bytes "abcdef", True, [ (3, nbytes "abc", True) ])
                , (Close         , True, [ (3, nbytes "def", True)
                                         , (3, eof         , False) ])
                ]
        it "like VC dns message" $ do
            testNBRecvNReadable
                [ (Bytes ("\x00\x07" <> "abcdefg"), True, [ (2, nbytes "\x00\x07", True)
                                                          , (7, nbytes "abcdefg" , False)
                                                          ])
                , (Close                          , True, [ (2, eof              , False) ])
                ]
{- FOURMOLU_ENABLE -}

-- old name for checking readable state
testNBRecvNReadable
    :: [(InEvent, Bool, [(Int, Result, Bool)])] -> IO ()
testNBRecvNReadable = testCtlRecvReadable

testCtlRecvReadable
    :: [(InEvent, Bool, [(Int, Result, Bool)])] -> IO ()
testCtlRecvReadable xs = do
    (readable, pushEv, rcv) <- mockSizedRecv
    ctlRecv <- controlledRecv <$> newControl (return False) <*> pure rcv
    readable `shouldReturn` False
    let check i j (sz, exnbr, exrd) = do
            let ix = show i ++ ": " ++ show j ++ ": "
            annotate (ix ++ "nbrecv result") $ ctlRecv sz `shouldReturn` exnbr
            annotate (ix ++ "readable after recv") $ readable `shouldReturn` exrd
        action i (ev, exrd0, ys) = do
            pushEv ev
            annotate (show i ++ ": readable after event") $ readable `shouldReturn` exrd0
            sequence_ $ zipWith (check i) [(1 :: Int) ..] ys
    sequence_ $ zipWith action [(1 :: Int) ..] xs

---

{- FOURMOLU_DISABLE -}
-- test cases, blocking controlledRecvVC
specCtlRecvVC :: Spec
specCtlRecvVC = do
    describe "controlledRecvVC" $ do
        it "eof" $ do
            testCtlRecvVC
                [ (Close, True, [ (eof', False) ])
                ]
        it "q1" $ do
            testCtlRecvVC
                [ ( Bytes ("\x00\x03" <> "abc")
                  , True, [ (rightVC "abc", False)
                          ])
                , ( Close
                  , True, [] )
                ]
        {-
        -- controlledRecvVC is blocked with chunked message
        it "q1-s" $ do
            testNBRecvVCReadable
                [ ( Bytes "\x00\x03"
                  , True, [ (NotEnough, False)
                          ])
                , ( Bytes "abc"
                  , True, [ (NBytes "abc", False)
                          ])
                , ( Close
                  , True, [] )
                ]
        -}
        it "q2" $ do
            testCtlRecvVC
                [ (Bytes ("\x00\x03" <> "abc" <> "\x00\x04" <> "defg")
                  , True, [ (rightVC "abc", True)
                          , (rightVC "defg", False)
                          ])
                , (Close
                  , True, [] )
                ]
        {-
        -- `controlledRecvVC` is blocked with chunked message
        it "q2-s" $ do
            testNBRecvVCReadable
                [ (Bytes ("\x00\x03" <> "abc")
                  , True, [ (NotEnough, True)
                          , (NBytes "abc", False)
                          ])
                , (Bytes ("\x00\x04" <> "defg")
                  , True, [ (NotEnough, True)
                          , (NBytes "defg", False)
                          ])
                , (Close
                  , True, [] )
                ]
        -}
{- FOURMOLU_ENABLE -}

type ResultVC = Either Terminate ByteString

rightVC :: String -> ResultVC
rightVC = Right . fromString

eof' :: ResultVC
eof' = Left EOF

testCtlRecvVC
    :: [(InEvent, Bool, [(ResultVC, Bool)])] -> IO ()
testCtlRecvVC xs = do
    (readable, pushEv, rcv) <- mockSizedRecv
    ctlRecvVC <- controlledRecvVC <$> newControl (return False) <*> pure rcv <*> pure 2048
    readable `shouldReturn` False
    let check i j (exnbr, exrd) = do
            let ix = show i ++ ": " ++ show j ++ ": "
            annotate (ix ++ "ctlRecvVC result") $ ctlRecvVC `shouldReturn` exnbr
            annotate (ix ++ "readable after recvVC") $ readable `shouldReturn` exrd
        action i (ev, exrd0, ys) = do
            pushEv ev
            annotate (show i ++ ": readable after event") $ readable `shouldReturn` exrd0
            sequence_ $ zipWith (check i) [(1 :: Int) ..] ys
    sequence_ $ zipWith action [(1 :: Int) ..] xs

------------------------------------------------------------

nbytes :: String -> Result
nbytes = NBytes . fromString

eof :: Result
eof = Terminate EOF

------------------------------------------------------------
-- chuncks mock

mockFromChunks :: [ByteString] -> IO (Int -> IO ByteString)
mockFromChunks xs0 = fst <$> mockFromChunks' xs0

mockFromChunks' :: [ByteString] -> IO (Int -> IO ByteString, IORef [ByteString])
mockFromChunks' xs0 = do
    ref <- newIORef xs0
    return (rcv ref, ref)
  where
    rcv ref n = do
        xss <- readIORef ref
        case xss of
            [] -> return mempty
            x : xs -> do
                writeIORef ref nexts
                return hd
              where
                (hd, tl) = BS.splitAt n x
                nexts
                  | tl == mempty = xs
                  | otherwise = tl : xs

------------------------------------------------------------
-- stream mock like readable network

data InEvent
    = Bytes String
    | Close
    deriving (Show)

data InState'
    = Arrived String
    | EndOfInput String
    | NoArrived
    deriving (Show)

type InState = IORef (Maybe InState')

{- FOURMOLU_DISABLE -}
readable' :: Maybe InState' -> Bool
readable' (Just (Arrived {}))     = True
readable' (Just  NoArrived)       = False
readable' (Just (EndOfInput {}))  = True
readable'  Nothing                = False

arrive :: IORef (Maybe InState') -> InEvent -> IO ()
arrive is e0 = do
    m <- readIORef is
    arrive' m e0
  where
    arrive' (Just (Arrived s0))     (Bytes s)   = writeIORef is $ Just $ Arrived (s0 ++ s)
    arrive' (Just (Arrived s0))      Close      = writeIORef is $ Just $ EndOfInput s0
    arrive' (Just  NoArrived)       (Bytes "")  = writeIORef is $ Just   NoArrived
    arrive' (Just  NoArrived)       (Bytes s)   = writeIORef is $ Just $ Arrived s
    arrive' (Just  NoArrived)        Close      = writeIORef is $ Just $ EndOfInput ""
    arrive' (Just (EndOfInput _))    e          = fail $ "wrong input state, input-event after eof: " ++ show e
    arrive'  Nothing                 e          = fail $ "wrong input state, input-event after closed: " ++ show e

consume :: IORef (Maybe InState') -> Int -> IO ByteString
consume is sz = do
    consume' =<< readIORef is
  where
    consume'  Nothing                = fail "cannot consume. after closed"
    consume' (Just NoArrived)        = fail "cannot consume. no-avail data, blocked"
    consume' (Just (EndOfInput ""))  = writeIORef is  Nothing $> mempty
    consume' (Just (EndOfInput s0))  = writeIORef is (Just next) $> fromString hd
      where
        next
            | null tl    = EndOfInput ""
            | otherwise  = EndOfInput tl
        (hd, tl) = splitAt sz s0
    consume' (Just (Arrived s0))     = writeIORef is (Just next) $> fromString hd
      where
        next
            | null tl    = NoArrived
            | otherwise  = Arrived tl
        (hd, tl) = splitAt sz s0
{- FOURMOLU_ENABLE -}

mockSizedRecv :: IO (IO Bool, InEvent -> IO (), Int -> IO ByteString)
mockSizedRecv = do
    inSt <- newIORef $ Just NoArrived
    let readable = readable' <$> readIORef inSt
    return (readable, arrive inSt, consume inSt)
