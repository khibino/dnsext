{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Serial where

import AtomicFile
import DNS.Types
import qualified Data.ByteString.Char8 as C8
import System.FilePath
import qualified System.IO.Error as E
import Text.Read

-- | The serial the zone is served with.
serialFile :: FilePath
serialFile = "serial"

-- | The serial of the upstream a signed zone was last transferred
--   from, which is what the upstream is asked about.
upstreamSerialFile :: FilePath
upstreamSerialFile = "upstream-serial"

saveSerial :: FilePath -> Serial -> IO ()
saveSerial zoneDir = saveSerialAs (zoneDir </> serialFile)

loadSerial :: FilePath -> IO (Maybe Serial)
loadSerial zoneDir = loadSerialAs (zoneDir </> serialFile)

saveUpstreamSerial :: FilePath -> Serial -> IO ()
saveUpstreamSerial zoneDir = saveSerialAs (zoneDir </> upstreamSerialFile)

loadUpstreamSerial :: FilePath -> IO (Maybe Serial)
loadUpstreamSerial zoneDir = loadSerialAs (zoneDir </> upstreamSerialFile)

saveSerialAs :: FilePath -> Serial -> IO ()
saveSerialAs file serial = writeAtomic file 0o644 str
  where
    str = C8.pack (show (unSerial serial)) <> "\n"

-- | Reading the stored serial.  The file is read strictly: with the lazy
--   'readFile' the handle stays open, because the digits are taken only
--   up to the newline and the rest is never demanded, and the following
--   'saveSerial' then fails with "resource busy (file is locked)".
loadSerialAs :: FilePath -> IO (Maybe Serial)
loadSerialAs file = do
    ebs <- E.tryIOError $ C8.readFile file
    case ebs of
        Left _ -> return Nothing
        Right bs -> case readMaybe $ C8.unpack $ C8.takeWhile isDigit bs of
            Nothing -> return Nothing
            Just n -> return $ Just $ Serial n
  where
    isDigit c = '0' <= c && c <= '9'

-- | The serial a signed zone is served with next: the upstream's where
--   it is ahead of ours, and ours advanced otherwise (RFC 1982).
nextSerial :: Serial -> Maybe Serial -> Serial
nextSerial upstream Nothing = upstream
nextSerial upstream (Just own)
    | upstream > own = upstream
    | otherwise = own <> Serial 1
