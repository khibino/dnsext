module DNS.TimeStamp where

import DNS.Types.Time (EpochTime, getCurrentTimeNsec)
import Data.Int (Int64)

data TimeStamp = TS EpochTime Int64
newtype DiffTime = DiffT Integer

getTimeStamp :: IO TimeStamp
getTimeStamp = uncurry TS <$> getCurrentTimeNsec

toNanosec :: TimeStamp -> Integer
toNanosec (TS e n) = fromIntegral e * nanof + fromIntegral n
  where
    nanof = 1000 * 1000 * 1000

diffTimeStamp :: TimeStamp -> TimeStamp -> DiffTime
diffTimeStamp t1 t2 = DiffT $ toNanosec t1 - toNanosec t2

showDiffSec1 :: DiffTime -> String
showDiffSec1 (DiffT snsec)
    | snsec < 0  = '-' : str ++ "s"
    | otherwise  = str ++ "s"
  where
    nsec = abs snsec
    df = 100 * 1000 * 1000
    dsec = nsec `quot` df
    (sec, d) = dsec `quotRem` 10
    str = show sec ++ "." ++ show d
