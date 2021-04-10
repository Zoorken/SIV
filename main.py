#!/usr/bin/python3
import argparse, os, stat, sqlite3, time, hashlib, csv
from pwd import getpwuid


class FileObj:
    def __init__(self, path):
        self.path = path
        self.st = self.setOsStat()
        self.accessRight = self.setAccessRight()
        self.size = self.setSize()
        self.userIdentiy = self.setUserIdentiy()
        self.groupIdentity = self.setGroupIdentity()
        self.lastModify = self.setLastModify()

    def setOsStat(self):
        return os.stat(self.path)

    def setAccessRight(self):
        return oct(stat.S_IMODE(self.st.st_mode)) #wwww.stomp.colorado.edu

    def setSize(self):
        return self.st.st_size

    def setUserIdentiy(self):
        return getpwuid(self.st.st_uid).pw_name

    def setGroupIdentity(self):
        return getpwuid(self.st.st_gid).pw_name

    def setLastModify(self):
        return self.st.st_mtime

    def getSizeInInt(self):
        return int(self.size)


def connect_db(filepath):
    print("db filepath: {}".format(filepath))
    return sqlite3.connect(filepath)


def dbCreateTable(filepath):
    cursor = connect_db(filepath)
    cursor.execute("CREATE table info (fPath TEXT UNIQUE, fileSize INT, userIdentidy TEXT, groupIdentity Text, acessRight Text, lastModify INT,hashMode Text, checked INT)")
    cursor.execute("CREATE table infoFolders (fPath TEXT UNIQUE, userIdentiy TEXT, groupIdentity TEXT, acessRight TEXT, lastModify INT, checked INT)")
    cursor.execute("CREATE table config (hashMode TEXT)")
    return cursor

def sethashTypeDB(cursor, hashType):
    cursor.execute("INSERT INTO config VALUES(?)",(hashType,))
    cursor.commit()
    print("HashMode: {}".format(hashType))


def getFileInfo(folder, cursor):
    nrOfDirs = 0
    nrOfFiles = 0
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        nrOfDirs += 1
        for name in files:
            nrOfFiles += 1
            filepath = os.path.join(root, name)
            fObj = FileObj(filepath)
            cHash = getFileHash(cursor, filepath)
            writeFileInfoToDb(fObj, cHash, cursor)

    cursor.commit()
    return (nrOfDirs, nrOfFiles)

def writeFileInfoToDb(f, cHash, cursor):
    cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?,?,0)",(f.path,f.size,f.userIdentiy,f.groupIdentity,f.accessRight,f.lastModify,cHash))

def getFileHash(cursor, filePath):
    hashType = getHashTypeDb(cursor)
    if hashType == "MD-5":
        return calcHash(filePath, hashlib.md5())
    elif hashType == "SHA-1":
        return calcHash(filePath, hashlib.sha1())
    else:
        print("ERROR: Unkown hashtype {}".format(hashType))
        quit()

def getHashTypeDb(cursor):
    cursor = cursor.execute('SELECT * FROM config')
    for row in cursor:
        return row[0]

def calcHash(fileName, hashObj):
    blocksize = 65536 # Reads a big chunck each time
    afile = open(fileName, 'rb') # Read file binary
    buf = afile.read(blocksize) # Read the first 65536 bytes
    while len(buf) > 0:
        hashObj.update(buf) # Att the buf to the function
        buf = afile.read(blocksize) # Large files needs iterating
    return hashObj.hexdigest() # Return the checksum

def getFolderInfo(folder, cursor):
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        for folderName in dirs:
            folderPath = os.path.join(root,folderName)
            writeFolderInfoToDb(folderPath, cursor)
    cursor.commit()

def writeFolderInfoToDb(folderPath, cursor):
    folderSt = os.stat(folderPath)
    acessRight = oct(stat.S_IMODE(folderSt.st_mode))
    userIdentiy = getpwuid(folderSt.st_uid).pw_name
    groupIdentity = getpwuid(folderSt.st_gid).pw_name
    lastModify = folderSt.st_mtime

    cursor.execute("INSERT INTO infoFolders VALUES(?,?,?,?,?,0)",(folderPath,userIdentiy,groupIdentity,acessRight,lastModify))


def getOldfileInfo(cursor,filepath):
    cursor = cursor.execute('SELECT * FROM info WHERE fPath=?',(filepath,))
    for row in cursor:
        return row

def getOldFolderInfo(cursor,filepath):
    cursor = cursor.execute('SELECT * FROM infoFolders WHERE fPath=?',(filepath,))
    for row in cursor:
        return row

def initializationReport(monitoreDirectory, pathVerification, nrOfDir, nrofFiles, startTime, reportFile):
    ss = "Monitored directory : {}\nVerification file : {}\nNr of directories : {}\n" \
         "Nr of files : {}\n".format(monitoreDirectory, pathVerification, str(nrOfDir), str(nrofFiles))

    with open(reportFile, "w") as f:
        ss += "Time to complete in seconds :" + calcElapsedTime(startTime) + "\n"
        f.write(ss)

def calcElapsedTime(startTime):
    return str(time.time() - startTime)

def initializationMode(args):
    print("Initialization mode\n")
    verifyInitInputIfValid(args)
    metadataExistUserDetermineWhatToDo(args.V)
    metadataExistUserDetermineWhatToDo(args.R)

    print("Creates new report file and verification file")
    startTime = time.time()

    cursor = dbCreateTable(args.V)
    sethashTypeDB(cursor, args.H)

    nrOfDirs, nrOfFiles = getFileInfo(args.D, cursor)
    getFolderInfo(args.D, cursor) # Get information about all the folders
    cursor.close() # close db connection
    initializationReport(args.D, args.V, nrOfDirs, nrOfFiles, startTime, args.R)
    print("Done with Initialization")



def verificationMode(args):
    print("Verification mode")
    abortMissingFile(args.V)
    metadataExistUserDetermineWhatToDo(args.R)
    ###########
    # Start verification process
    ##########
    startTime = time.time()
    cursor = connect_db(args.V)

    nrOfWarnings, nrOfDirs, nrOfFiles, ssChangedFiles = compare(args.D, cursor)
    nrOfWarnings, ssChangedFiles = compareFolders(args.D, cursor, nrOfWarnings)
    nrOfWarnings, ssChangedFiles = deletedFiles(cursor, nrOfWarnings, ssChangedFiles)
    nrOfWarnings, ssChangedFiles = deletedFolders(cursor, nrOfWarnings, ssChangedFiles)

    reportFileVerification(startTime, args.D, args.V, args.R, nrOfDirs, nrOfFiles, nrOfWarnings, ssChangedFiles)
    # Clean up
    cursor.execute('UPDATE info SET checked=? WHERE checked =?',(0,1)) # Changed it back
    cursor.commit() # Change it back

def abortMissingFile(f):
    if not os.path.isfile(f):
        print("ERROR: The file: {} is missing.".format(f))
        quit()

def metadataExistUserDetermineWhatToDo(f):
    if os.path.isfile(f):
        q = "Should we overwrite file: {} yes/no : ".format(f)
        if userChoiceYesOrNo(q) == "no":
            print("We can't continue, try again with different file input")
            quit()
        else:
            os.remove(f)

def compare(folder, cursor):
    nrOfDirs = 0
    nrOfFiles = 0
    nrOfWarnings = 0
    ssChangedFiles = ""
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        nrOfDirs += 1
        for name in files:
            nrOfFiles += 1
            filepath = os.path.join(root, name)
            dbFileInfo = getOldfileInfo(cursor, filepath)

            if dbFileInfo is None:
                nrOfWarnings += 1
                print("NEW FILE: {}".format(filepath))
                ssChangedFiles += "NEW FILE: {}\n".format(filepath)
            else:
                # Retrive latest information about files
                cHash = getFileHash(cursor, filepath)
                errorMsg = compareWithDbFile(filepath, cHash, dbFileInfo)

                if errorMsg:
                    nrOfWarnings += 1
                    ssChangedFiles += errorMsg + "\n"

                cursor.execute('UPDATE info SET checked=? WHERE fPath =?',(1,filepath))
        cursor.commit()

    return (nrOfWarnings,nrOfDirs,nrOfFiles,ssChangedFiles)

def compareWithDbFile(filepath, cHash, dbFile):
    diff = False
    fileObj = FileObj(filepath)
    eMsg = ''
    if dbFile[5] != fileObj.lastModify:
        diff = True
        eMsg += ", prev changes where made {} new changes {}".format(dbFile[5], fileObj.lastModify)
    if dbFile[1] != fileObj.getSizeInInt():
        diff = True
        eMsg += ", fileSize from {} to {}".format(dbFile[1], fileObj.getSizeInInt())
    if dbFile[2] != fileObj.userIdentiy:
        diff = True
        eMsg += ", useridentify from {} to {}".format(dbFile[2], fileObj.userIdentiy)
    if dbFile[3] != fileObj.groupIdentity:
        diff = True
        eMsg += ", groupidentiy from {} to {}".format(dbFile[3], fileObj.groupIdentity)
    if dbFile[4] != str(fileObj.accessRight):
        diff = True
        eMsg += ", accessright from {} to {}".format(dbFile[4], fileObj.accessRight)
    if dbFile[6] != cHash:
        diff = True
        eMsg += ", file content compromised, hash differ"

    if diff:
        eMsg = "CHANGED: File {} ".format(fileObj.path) + eMsg
        print(eMsg + "\n")

    return eMsg

def compareFolders(folder, cursor, nrOfWarnings):
    ssChangedFiles = ""
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        for name in dirs:
            itemChanged = False
            fPath = os.path.join(root, name)
            oldInfo = getOldFolderInfo(cursor,fPath)

            if oldInfo == None:
                nrOfWarnings +=1
                print("NEW FOLDER: {}".format(fPath))
                ssChangedFiles += "NEW FOLDER: {}\n".format(fPath)
            else:
                # Retrive latest information about files
                st = os.stat(fPath)
                acessRight = oct(stat.S_IMODE(st.st_mode)) #wwww.stomp.colorado.edu
                userIdentiy = getpwuid(st.st_uid).pw_name
                groupIdentity = getpwuid(st.st_gid).pw_name
                lastModify = st.st_mtime

                #Compare the files with the one in db
                errorMsg = "CHANGED: Folder {} ".format(fPath)
                if oldInfo[1] != userIdentiy:
                    itemChanged = True
                    errorMsg += ", useridentify from {} to {}".format(oldInfo[1], userIdentiy)
                if oldInfo[2] != groupIdentity:
                    itemChanged = True
                    errorMsg += ", groupidentiy from {} to {}".format(oldInfo[2], groupIdentity)
                if oldInfo[3] != str(acessRight):
                    itemChanged = True
                    errorMsg += ", accessright from {} to {}".format(oldInfo[3], acessRight)
                if oldInfo[4] != lastModify:
                    itemChanged = True
                    errorMsg += ", prev changes where made {} new changes {}".format(oldInfo[4], lastModify)
                    # File has been modified from db version

                if itemChanged:
                    nrOfWarnings +=1
                    print(errorMsg + "\n")
                    ssChangedFiles += errorMsg + "\n"

                cursor.execute('UPDATE infoFolders SET checked=? WHERE fPath =?',(1,fPath))
        cursor.commit()

    return (nrOfWarnings,ssChangedFiles)

def deletedFiles(cursor, nrOfWarnings, ssChangedFiles):
    cursor = cursor.execute('SELECT * FROM info WHERE checked=?',(0,))
    for row in cursor:
        nrOfWarnings += 1
        print("File deleted: {}".format(row[0]))
        ssChangedFiles += "File deleted: {}\n".format(row[0])

    return (nrOfWarnings, ssChangedFiles)

def deletedFolders(cursor, nrOfWarnings, ssChangedFiles):
    cursor = cursor.execute('SELECT * FROM infoFolders WHERE checked=?',(0,))
    for row in cursor:
        nrOfWarnings += 1
        print("Folder deleted: {}".format(row[0]))
        ssChangedFiles += "Folder deleted: {}\n".format(row[0])
    return (nrOfWarnings, ssChangedFiles)

def reportFileVerification(startTime, monitoreDirectory, pathVerification, reportFile, nrOfDir, nrOfFiles, nrOfWarnings, ssChangedFiles):
    ss = "Monitored directory: " + os.path.abspath(monitoreDirectory) + "\nVerification file: " + os.path.abspath(pathVerification) + "\nReport file: "+ os.path.abspath(reportFile) + "\nNr of directorys: " + str(nrOfDir) + "\nNr of files: " + str(nrOfFiles) + "\nNr of warnings: " + str(nrOfWarnings)
    with open(reportFile, 'w') as f:
        elapsedTime = time.time() - startTime
        ss += "\nTime to complete in seconds: " + str(int(round(elapsedTime))) + "\n"
        ss += ssChangedFiles
        f.write(ss)

def verifyInitInputIfValid(args):
    if args.H not in ['MD-5', 'SHA-1']:
        print("You must choose a hash function either, -H SHA-1 or MD5")
        quit()

    if os.path.isfile(args.V) or os.path.isfile(args.R):
        question = "Should we overwrite verification {} and report {} yes/no : ".format(args.V, args.R)
        if userChoiceYesOrNo(question) == "no":
            print("The files will be preserved, goodbye")
            quit()
        else:
            removeFile(args.V)
            removeFile(args.R)

def userChoiceYesOrNo(question):
    ans = ""
    while(ans not in ["yes", "no"]):
        ans = input(question)
    return ans

def removeFile(f):
    if os.path.isfile(f):
        os.remove(f)
        print("Deleted {}".format(f))

def verifyCommonInputAbortIfInvalid(args):
    inputMonitoredDirectoryValid(args)
    inputDirNotInMetadataFiles(args.D, args.V, args.R)
    inputIsDir(args.V, '-V')
    inputIsDir(args.R, '-R')
    print("Verification and report ok")

def inputMonitoredDirectoryValid(args):
    if not os.path.isdir(args.D):
        print("Directory {} is not existing".format(args.D))
        quit()

def inputDirNotInMetadataFiles(directory, verification, report):
    if directory in verification and directory in report:
        print("Verification: {}\n Report: {} \n can't be inside: " +
              "directory {}\n please specify outside {}".format(verification, report, directory, directory))
        quit()

def inputIsDir(argument, f):
    if os.path.isdir(f):
        print("Argument [{}] value is not a file [{}]".format(argument, f))
        quit()

def argumentParser():
    parser = argparse.ArgumentParser(description="Use the program in either Initialization or Verification mode:\n" +
        "Example Initialization: siv -i -D important_directory -V verificationDB -R my_repoirt.txt -H sha1\n" +
        "Example Verification: siv -v -D important_directory -V verificationDB -R my_report2.txt")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", help="Initialization mode", action="store_true")
    group.add_argument("-v", help="Verification mode", action="store_true")
    parser.add_argument("-D", help="Monitored directory", required=True)
    parser.add_argument("-V", help="Verification file, not in monitored directory", required=True)
    parser.add_argument("-R", help="Report file, not in monitored directory", required=True)
    parser.add_argument("-H", help="Hash function", choices=["SHA-1", "MD-5"])
    return parser.parse_args()

def main():
    args = argumentParser()
    verifyCommonInputAbortIfInvalid(args)
    if args.i:
        initializationMode(args)
    elif args.v:
        verificationMode(args)

if __name__ == "__main__":
    main()
