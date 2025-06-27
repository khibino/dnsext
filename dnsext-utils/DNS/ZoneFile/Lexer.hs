{-# LANGUAGE NoStrict #-}
{-# LANGUAGE FlexibleContexts #-}

module DNS.ZoneFile.Lexer where

-- ghc packages
import Control.Applicative
import Control.Monad
import qualified Data.ByteString.Lazy as LB
import Numeric (readOct)

-- other packages
import Data.Word8

-- this package
import DNS.Parser hiding (Parser)
import qualified DNS.Parser as Poly
import DNS.ZoneFile.Types

type LBS = LB.ByteString
type W8 = Word8
type Parser a = Poly.Parser LBS a

byte_token :: Parser Word8
byte_token = token

byte :: MonadParser W8 s m => Word8 -> m Word8
byte = this

charByte :: MonadParser W8 s m => Char -> m Word8
charByte c = satisfy "charByte" ((== c) . w8toChar)

string :: MonadParser W8 s m => String -> m [Word8]
string = mapM charByte

---

-- RFC 1035 5.1 Format

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> :seti -XTypeApplications
-- >>> :seti -Wno-name-shadowing
-- >>> import Data.String (fromString)
-- >>> import Data.Either (isLeft, isRight)
-- >>> import Text.Printf (printf)
-- >>> runParser = Poly.runParser @LBS

isSpc :: Word8 -> Bool
isSpc = (||) <$> (== _tab) <*> (== _space)

isNewline :: Word8 -> Bool
isNewline = (||) <$> (== _cr) <*> (== _lf)

-- |
-- >>> runParser spc " abc"
-- Right ((),"abc")
-- >>> runParser spc "\tpqr"
-- Right ((),"pqr")
-- >>> isLeft $ runParser spc "abc"
-- True
spc :: MonadParser W8 s m => m ()
spc = void $ satisfy "tab or space" isSpc

{- FOURMOLU_DISABLE -}
-- |
-- >>> runParser lineComment "; example"
-- Right ((),"")
-- >>> isLeft $ runParser lineComment "abc; example"
-- True
lineComment :: MonadParser W8 s m => m ()
lineComment = void( byte _semicolon *> many not_nl )
  where not_nl = satisfy "not newline" $ not . isNewline

-- |
-- >>> runParser newline "\n"
-- Right ((),"")
-- >>> runParser newline "\r\n"
-- Right ((),"")
-- >>> runParser newline "\r"
-- Right ((),"")
newline :: MonadParser W8 s m => m ()
newline =
    void
    ( byte _cr *> byte _lf  <|>
      byte _cr              <|>
      byte _lf )

-- | not escaped, not quoted, byte
-- >>> runParser cstringbSimple "abc"
-- Right (97,"bc")
-- >>> charset = "-+:" ++ ['0'..'9'] ++ ['A'..'Z'] ++ ['a'..'z']
-- >>> all isRight $ map (runParser (cstringbSimple <* eof) . fromString . (:"")) charset
-- True
-- >>> isLeft $ runParser cstringbSimple "."
-- True
-- >>> all isLeft $ map (runParser (cstringbSimple <* eof) . fromString . (:"")) ".;()\\\" \n"
-- True
cstringbSimple :: MonadParser W8 s m => m Word8
cstringbSimple = satisfy "not (`.` || `;` || `\\` || `\"`) && not `space` && not `newline` && isPrint && isAscii" check
  where
    check c =
        c `notElem` [_period, _at, _semicolon, _parenleft, _parenright, _backslash, _quotedbl] &&
        not (isSpc c) &&
        not (isNewline c) && isPrint c && isAscii c
{- FOURMOLU_ENABLE -}

backslash :: MonadParser W8 s m => m ()
backslash = void $ byte _backslash

{- FOURMOLU_DISABLE -}
-- | backslash escaped byte
-- >>> runParser cstringbEscaped "\\abc"
-- Right (97,"bc")
-- >>> charset = " \t.\\\"" ++ "-+:" ++ ['A'..'Z'] ++ ['a'..'z']
-- >>> escaped c = fromString $ '\\':c:""
-- >>> all isRight $ map (runParser (cstringbEscaped <* eof) . escaped) charset
-- True
-- >>> isLeft $ runParser cstringbEscaped "\\\n"
-- True
cstringbEscaped :: MonadParser W8 s m => m Word8
cstringbEscaped = backslash *> satisfy "not isDigit && not `newline` && isPrint && isAscii || tab" check
  where check c = not (isDigit c) && not (isNewline c) && isPrint c && isAscii c || c == _tab

-- | octal represented byte
-- >>> runParser cstringbOct "\\177"
-- Right (127,"")
-- >>> runParser cstringbOct "\\377"
-- Right (255,"")
-- >>> escapedOct i = fromString $ '\\' : printf "%03o" i
-- >>> octProp i = runParser cstringbOct (escapedOct i) == Right (i, "")
-- >>> all octProp [0..255]
-- True
cstringbOct :: MonadParser W8 s m => m Word8
cstringbOct = backslash *> (replicateM 3 oct >>= getOct)
  where
    oct = satisfy "isOctDigit" isOctDigit
    getOct ws = case [ v | (v, "") <- readOct $ map w8toChar ws ] of
        []     -> raise ""
        v : _  -> pure v
-- |
-- >>> runParser cstringByte "zyx"
-- Right (122,"yx")
-- >>> runParser cstringByte "\\\t"
-- Right (9,"")
-- >>> runParser cstringByte "\\200"
-- Right (128,"")
cstringByte :: MonadParser W8 s m => m Word8
cstringByte =
    cstringbSimple    <|>
    cstringbOct       <|>
    cstringbEscaped

quote :: MonadParser W8 s m => m ()
quote = void $ byte _quotedbl

quotedByte :: MonadParser W8 s m => m Word8
quotedByte =
    cstringbSimple    <|>
    cstringbOct       <|>
    cstringbEscaped   <|>
    satisfy "not (`\\` || `\"`) && not newline && isPrint || tab" check
  where
    check c =
        c `notElem` [_backslash, _quotedbl] &&
        not (isNewline c) && isPrint c && isAscii c
        || c == _tab
{- FOURMOLU_ENABLE -}

directive :: MonadParser W8 s m => m Directive
directive = D_Origin <$ string "$ORIGIN" <|> D_TTL <$ string "$TTL"

{- FOURMOLU_DISABLE -}
-- |
--
-- >>> runParser lex_cstring "abc"
-- Right ("abc","")
-- >>> runParser lex_cstring "\"y.z\""
-- Right ("y.z","")
lex_cstring :: MonadParser W8 s m => m CString
lex_cstring =
    cstringW8 <$>
    ( some cstringByte                  <|>
      quote *> many quotedByte <* quote )
{- FOURMOLU_ENABLE -}

comment :: MonadParser W8 s m => m ()
comment = void (many spc *> lineComment *> optional newline)

{- FOURMOLU_DISABLE -}
lexerToken :: MonadParser W8 s m => m Token
lexerToken =
    Directive <$> directive     <|>
    At <$ byte _at              <|>
    LParen <$ byte _parenleft   <|>
    RParen <$ byte _parenright  <|>
    Blank <$ some spc           <|>
    Dot <$ byte _period         <|>
    CS <$> lex_cstring          <|>
    Comment <$ comment
{- FOURMOLU_ENABLE -}

-- |
-- >>> lexLine "example.com. 7200 IN A 203.0.113.3  ; example record"
-- Right [CS "example",Dot,CS "com",Dot,Blank,CS "7200",Blank,CS "IN",Blank,CS "A",Blank,CS "203",Dot,CS "0",Dot,CS "113",Dot,CS "3",Blank,Comment]
lexLine :: LB.ByteString -> Either String [Token]
lexLine = (fst <$>) . runParser (many lexerToken <* eof)
