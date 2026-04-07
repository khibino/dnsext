
module DNS.Exception (
    -- * Not to catch async exceptions
    catchSafe',
    catchSafe,
    handleSafe',
    handleSafe,
    trySafe',
    trySafe,
) where

import Control.Exception

{- FOURMOLU_DISABLE -}
catchSafe0
    :: (SomeException -> IO ())
    -> IO a -> (SomeException -> IO a) -> IO a
catchSafe0 logEx action h0 =
    catch action (\se -> logEx se >> h1 se)
  where
    -- SomeException: asynchronous exceptions are re-thrown
    h1 se
        | Just (SomeAsyncException _) <- fromException se  = throwIO se
        | otherwise                                        = h0 se
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- |
-- >>> catchSafe' putStrLn "case1" (fail "foo") print >> return "result"
-- ...user error (foo)...case1...
-- user error (foo)
-- "result"
-- >>> catchSafe' putStrLn "case2" (throwIO ThreadKilled) print >> return "result"
-- ...thread killed...case2...
-- *** Exception: thread killed
-- ...
catchSafe'
    :: (String -> IO ())
    -> String
    -> IO a -> (SomeException -> IO a) -> IO a
catchSafe' logLn ~tag action h0 = catchSafe0 logEx action h0
  where
    logEx se = logLn ("DNS.catchSafe: " ++ show se ++ ": " ++ tag)
{- FOURMOLU_ENABLE -}

catchSafe :: IO a -> (SomeException -> IO a) -> IO a
catchSafe = catchSafe0 (\_ -> return ())

{- FOURMOLU_DISABLE -}
handleSafe'
    :: (String -> IO ())
    -> String
    -> (SomeException -> IO a) -> IO a -> IO a
handleSafe' logLn ~tag = flip (catchSafe' logLn tag)
{- FOURMOLU_ENABLE -}

handleSafe :: (SomeException -> IO a) -> IO a -> IO a
handleSafe = flip catchSafe

{- FOURMOLU_DISABLE -}
trySafe'
    :: (String -> IO ())
    -> String
    -> IO a -> IO (Either SomeException a)
trySafe' logLn ~tag action = catchSafe' logLn tag (action >>= \v -> return (Right v)) (\e -> return (Left e))
{- FOURMOLU_ENABLE -}

trySafe :: IO a -> IO (Either SomeException a)
trySafe action = catchSafe (action >>= \v -> return (Right v)) (\e -> return (Left e))
