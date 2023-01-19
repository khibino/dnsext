{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.QUIC where

import DNS.Do53.Internal
import Network.QUIC
import Network.QUIC.Client

import DNS.DoX.Common

quicResolver :: Resolver
quicResolver ri@ResolvInfo{..} q qctl = vcResolver "QUIC" perform ri q qctl
  where
    cc = getQUICParams rinfoHostName rinfoPortNumber "doq"
    perform solve = run cc $ \conn -> do
        strm <- stream conn
        let sendDoQ bs = do
                sendVC (sendStreamMany strm) bs
                shutdownStream strm
            recvDoQ = recvVC $ recvStream strm
        solve sendDoQ recvDoQ
