{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module LinuxCap (
    -- * interface to setup effective capability
    Cap,
    CapValue (..),
    setupEffective,
    setupEffective',

    -- * interface to libcap fucs
    CapFlag (..),
    --
    capFreeCap,
    withCurrentCap,
    capFreeText,
    withCapText,
    setProc,
    --
    getFlag,
    queryFlags,
    setFlag,

    -- * low-level, thin wrapper to C
    CCapValue (..),
    CCapFlag (..),
    CCapFlagValue (..),
    --
    toCCapValue,
    toCCapFlag,
    --
    c_CAP_NET_BIND_SERVICE,
    --
    c_CAP_EFFECTIVE,
    c_CAP_PERMITTED,
    c_CAP_INHERITABLE,
    --
    c_CAP_CLEAR,
    c_CAP_SET,
    --
    c_cap_free,
    c_cap_get_proc,
    c_cap_to_text,
    c_cap_set_proc,
    c_cap_get_flag,
    c_cap_set_flag,

) where

import Control.Exception (bracket)
import Control.Monad
import Data.Functor
import System.IO.Error (tryIOError)

import Foreign (Ptr, Storable (..), alloca, allocaArray, nullPtr, peek)
import Foreign.C (CInt (..), CString, peekCString, throwErrno)

#include <HsLinuxCap.h>

------------------------------------------------------------

newtype CCapValue = CCapValue CInt deriving (Eq, Show, Storable)

#{enum CCapValue, CCapValue
, c_CAP_NET_BIND_SERVICE = CAP_NET_BIND_SERVICE
}

data CapValue
    = CAP_NET_BIND_SERVICE
    deriving (Eq, Show)

toCCapValue :: CapValue -> CCapValue
toCCapValue CAP_NET_BIND_SERVICE = c_CAP_NET_BIND_SERVICE

newtype CCapFlag = CCapFlag CInt deriving (Eq, Show)

#{enum CCapFlag, CCapFlag
, c_CAP_EFFECTIVE    = CAP_EFFECTIVE
, c_CAP_PERMITTED    = CAP_PERMITTED
, c_CAP_INHERITABLE  = CAP_INHERITABLE
}

data CapFlag
    = CAP_EFFECTIVE
    | CAP_PERMITTED
    | CAP_INHERITABLE
    deriving (Eq, Show)

toCCapFlag :: CapFlag -> CCapFlag
toCCapFlag cf = case cf of
  CAP_EFFECTIVE    -> c_CAP_EFFECTIVE
  CAP_PERMITTED    -> c_CAP_PERMITTED
  CAP_INHERITABLE  -> c_CAP_INHERITABLE

newtype CCapFlagValue = CCapFlagValue CInt deriving (Eq, Show, Storable)

#{enum CCapFlagValue, CCapFlagValue
, c_CAP_CLEAR  = CAP_CLEAR
, c_CAP_SET    = CAP_SET
}

data CapStruct  {- target phantom type to Ptr -}
newtype Cap = Cap (Ptr CapStruct) deriving Show

newtype CapText = CapText CString deriving Show

------------------------------------------------------------

foreign import ccall safe "sys/capability.h cap_free"
  c_cap_free :: Ptr a -> IO CInt

unsafeCapFree :: Ptr a -> IO ()
unsafeCapFree ptr = do
    rc <- c_cap_free ptr  {- using errno, set by cap_free -}
    when (rc < 0) $ throwErrno "capability: cap_free"

------------------------------------------------------------

foreign import ccall safe "sys/capability.h cap_get_proc"
  c_cap_get_proc :: IO Cap

capFreeCap :: Cap -> IO ()
capFreeCap (Cap ptr) = unsafeCapFree ptr

-- |
-- Action using current Cap state
withCurrentCap :: (Cap -> IO a) -> IO a
withCurrentCap = bracket get_proc capFreeCap
  where
    get_proc = do
        cap@(Cap ptr) <- c_cap_get_proc  {- cap_get_proc does not set errno -}
        when (ptr == nullPtr) $ fail "capability: cap_get_proc: failed"
        pure cap

foreign import ccall safe "sys/capability.h cap_to_text"
  c_cap_to_text :: Cap -> Ptr CInt -> IO CapText

capFreeText :: CapText -> IO ()
capFreeText (CapText ptr) = unsafeCapFree ptr

withCapText :: Cap -> (String -> IO a) -> IO a
withCapText cap h =
    {- Dons comment, `peekCString` is strict
       https://stackoverflow.com/questions/1739186/are-peekcstring-and-peekcstringlen-lazy/1739331#1739331  -}
    bracket tget capFreeText $ \(CapText cs) -> peekCString cs >>= h
  where
    tget = c_cap_to_text cap nullPtr

foreign import ccall safe "sys/capability.h cap_set_proc"
  c_cap_set_proc :: Cap -> IO CInt

-- |
-- Update Cap state
setProc :: Cap -> IO ()
setProc cap = do
    rc <- c_cap_set_proc cap
    when (rc < 0) $ throwErrno "capability: cap_set_proc"

------------------------------------------------------------

foreign import ccall safe "sys/capability.h cap_get_flag"
  c_cap_get_flag :: Cap -> CCapValue -> CCapFlag -> Ptr CCapFlagValue -> IO CInt

-- |
-- Read flag from Cap type memory structure
getFlag :: Cap -> CapValue -> CapFlag -> IO Bool
getFlag cap cval cflag = dispatch =<< alloca get_flag
  where
    mkBanner ct = pure $ unwords ["capability:", "cap_get_flag", ct, show cval, show cflag]
    error' throw s = withCapText cap mkBanner >>= \ban -> throw $ ban ++ ": " ++ s
    get_flag fvp = do
        rc <- c_cap_get_flag cap (toCCapValue cval) (toCCapFlag cflag) fvp
        when (rc < 0) $ error' throwErrno $ "failed, rc: " ++ show rc
        peek fvp
    dispatch fv
        | fv == c_CAP_CLEAR  = pure False
        | fv == c_CAP_SET    = pure True
        | otherwise          = error' fail $ "unknown flag value result: " ++ show fv

-- |
-- Read set flags from Cap type memory structure
queryFlags :: Cap -> CapValue -> [CapFlag] -> IO [CapFlag]
queryFlags cap cval cflags = do
    xs <- sequence [(,) f <$> getFlag cap cval f | f <- cflags]
    pure [f | (f, fv) <- xs, fv]

foreign import ccall safe "sys/capability.h cap_set_flag"
  c_cap_set_flag :: Cap -> CCapFlag -> CInt -> Ptr CCapValue -> CCapFlagValue -> IO CInt

-- |
-- Write flag to Cap type memory structure, so not modify current Cap state
setFlag :: Cap -> CapFlag -> [CapValue] -> Bool -> IO ()
setFlag cap cflag cvals cfset = allocaArray n set_flag
  where
    n = length cvals
    cfv
        | cfset      = c_CAP_SET
        | otherwise  = c_CAP_CLEAR
    mkBanner ct = pure $ unwords ["capability:", "cap_set_flag", ct, show cflag, show cvals, show cfv]
    set_flag buf = do
        zipWithM_ (pokeElemOff buf) [0..] (map toCCapValue cvals)
        rc <- c_cap_set_flag cap (toCCapFlag cflag) (fromIntegral n) buf cfv
        when (rc < 0) $ withCapText cap mkBanner >>= \ban -> throwErrno $ ban ++ ": failed rc: " ++ show rc

------------------------------------------------------------

-- |
-- Same as `setupEffective` except for throwing `IOError` on low-level error cases
setupEffective' :: (String -> IO ()) -> CapValue -> IO Bool
setupEffective' logLn cval  = withCurrentCap $ \cap ->
    dispatch cap =<< queryFlags cap cval [CAP_PERMITTED, CAP_EFFECTIVE]
  where
    logLn' s = logLn $ "capability.setup-effective: " ++ s
    setup cap = setFlag cap CAP_EFFECTIVE [CAP_NET_BIND_SERVICE] True *> setProc cap
    dispatch cap flags
        | CAP_PERMITTED    `elem` flags &&
          CAP_EFFECTIVE `notElem` flags    = setup cap *> logLn' ("effective enabled: " ++ show cval)  $> True
        | CAP_EFFECTIVE    `elem` flags    =              logLn' ("already effective: " ++ show cval)  $> True
        | otherwise                        =              logLn' ("not permitted: "     ++ show cval)  $> False

-- |
-- example: setupEffecive putStrLn CAP_NET_BIND_SERVICE
--
-- Setup effective capability for specified `CapValue` like `CAP_NET_BIND_SERVICE`.
-- The result is `True` if enabling the `CAP_EFFECTIVE` capability succeeds; otherwise, it is `False`.
setupEffective :: (String -> IO ()) -> CapValue -> IO Bool
setupEffective logLn cval = do
    let failed e = logLn ("capability.setup-effective: " ++ show e) $> False
    either failed pure =<< tryIOError (setupEffective' logLn cval)

------------------------------------------------------------
