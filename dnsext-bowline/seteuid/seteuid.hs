
import System.Posix (
    getGroupEntryForName,
    getRealUserID,
    getUserEntryForName,
    setGroupID,
    groupID,
    getEffectiveUserID,
    setUserID,
    userID,
    getEffectiveGroupID,
 )

-- | Checking if this process has the root privilege.
amIrootUser :: IO Bool
amIrootUser = (== 0) <$> getRealUserID

-- | Setting user and group.
setGroupUser
    :: String
    -- ^ User
    -> String
    -- ^ Group
    -> IO Bool
setGroupUser user group = do
    root <- amIrootUser
    if root
        then do
            gid <- getGroupEntryForName group
            putStrLn $ group ++ "=" ++ show gid
            setGroupID $ groupID gid
            uid <- getUserEntryForName user
            putStrLn $ user ++ "=" ++ show uid
            setUserID $ userID uid
            return True
        else
            return False


main :: IO ()
main = do
    putStrLn "-----------------------"
    _ <- setGroupUser "nobody" "nogroup"
    putStrLn . ("euid: " ++) . show =<< getEffectiveUserID
    putStrLn . ("egid: " ++) . show =<< getEffectiveGroupID
