{-# LANGUAGE FlexibleContexts #-}

module DNS.ZoneFile.ParserBase where

import Control.Applicative
import Control.Monad
import qualified Data.ByteString.Short as Short

-- this package
import DNS.Parser
import DNS.ZoneFile.Types

-- |
-- >>> runParser dot [Dot]
-- Right (Dot,[])
dot :: MonadParser Token s m => m Token
dot = this Dot

-- |
-- >>> runParser blank [Blank]
-- Right (Blank,[])
blank :: MonadParser Token s m => m Token
blank = this Blank

{- FOURMOLU_DISABLE -}
lstring :: MonadParser Token s m => m CS'
lstring = do
    t <- token
    case t of
        CS cs  -> pure cs
        _      -> raise $ "Parser.lstring: not CString token: " ++ show t

cstring' :: MonadParser Token s m => m CS'
cstring' = do
    cs <- lstring
    guard (Short.length (cs_cs cs) < 256) <|> raise ("Parser.cstring: too long: " ++ show cs)
    pure cs

cstring :: MonadParser Token s m => m CString
cstring = cs_cs <$> cstring'
{- FOURMOLU_ENABLE -}

readCString :: (Read a, MonadParser Token s m) => String -> m a
readCString name = readable ("Zonefile." ++ name) . fromCString =<< cstring
