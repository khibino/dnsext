{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.NSECxRange where

-- dnsext-types
import DNS.Types

-- this package
import DNS.SEC.Imports
import DNS.SEC.Types

withSectionRanges
    :: (Show r, Ord a)
    => (ResourceRecord -> Maybe (Either String r))
    -> TYPE
    -> (r -> a)
    -> (r -> a)
    -> [ResourceRecord]
    -> (String -> b)
    -> ([(ResourceRecord, r, [RD_RRSIG])] -> b)
    -> b
withSectionRanges takeRange nsecTy lower upper srrs leftK rightK = either leftK rightK $ do
    ranges0 <- getRanges
    ranges <- uniqueRanges (lower . snd) (upper . snd) ranges0
    zipSigs ranges sigSets
  where
    getRanges = sequence [(,) rr <$> getRange | rr <- srrs, Just getRange <- [takeRange rr]]
    sigSets = [(rrn, map snd g) | g@((rrn, _) : _) <- groupBy ((==) `on` fst) $ sortOn fst sigs]
    sigs = [(rrname rr, rd) | rr <- srrs, rrtype rr == RRSIG, Just rd@RD_RRSIG{..} <- [fromRData $ rdata rr], rrsig_type == nsecTy]
    zipSigs [] [] = Right []
    zipSigs [] ((_, ss) : _) = errorOrphanRRSIG ss
    zipSigs ((rr, _) : _) [] = errorNoRRSIG rr
    zipSigs ((rr, range) : rs) ((rrn, ss) : sgs) = do
        when (rrname rr < rrn) $ errorNoRRSIG rr
        when (rrname rr > rrn) $ errorOrphanRRSIG ss
        zs <- zipSigs rs sgs
        Right $ (rr, range, ss) : zs
    errorNoRRSIG rr = Left $ "with-section-ranges: " ++ show nsecTy ++ " without RRSIG found: " ++ show rr
    errorOrphanRRSIG ss = Left $ "with-section-ranges: orphan RRSIGs found: " ++ show ss

---

uniqueRanges :: (Show r, Ord a) => (r -> a) -> (r -> a) -> [r] -> Either String [r]
uniqueRanges lower upper ranges0 = case reverse ranges of
    [] -> Right []
    x : rs
        | not goodOrder -> Left $ "unique-ranges: not good ordered range found: " ++ show notOrdered
        | overlap -> Left $ "unique-ranges: overlapped range found: " ++ show overlapped
        | otherwise -> Right ranges
      where
        rotated = lower x > upper x {- only max range is allowed to be rotated -}
        --
        {- checking lower bound and upper bound is ordered -}
        orders = (order x || rotated, x) : map ((,) <$> order <*> id) rs
        notOrdered = map snd $ filter (not . fst) orders
        goodOrder = all fst orders
        --
        {- checking ranges is not overlapped -}
        nexts
            | rotated = tail ranges ++ [head ranges]
            | otherwise = tail ranges
        overlaps = [(upper r > lower n, (r, n)) | (r, n) <- zip ranges nexts]
        overlap = or $ map fst overlaps
        overlapped = map snd $ filter fst overlaps
  where
    ranges = sortOn lower ranges0
    order r = lower r < upper r
