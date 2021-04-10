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

class DiffReport:
    def __init__(self):
        self.dirs = 0
        self.files = 0
        self.ssChangedFiles = ""
        self.warnings = 0

    def __add__(self, other):
        self.dirs += other.dirs
        self.files += other.files
        self.ssChangedFiles += other.ssChangedFiles
        self.warnings += other.warnings
        return self

    def incrementDirs(self):
        self.dirs += 1

    def incrementFiles(self):
        self.files += 1

    def appendChangedFile(self, ssChangedFile):
        self.ssChangedFiles += ssChangedFile

    def incrementWarnings(self):
        self.warnings += 1

    def getSSReport(self):
        return f"Nr of directories: {self.dirs}\nNr of files: {self.files}\nNr of warnings: {self.warnings}\n{self.ssChangedFiles}"


class DB:

    @staticmethod
    def connect(filepath):
        print("db filepath: {}".format(filepath))
        return sqlite3.connect(filepath)


    @staticmethod
    def createTable(cursor):
        cursor.execute("CREATE table info (fPath TEXT UNIQUE, fileSize INT, userIdentidy TEXT, groupIdentity Text, acessRight Text, lastModify INT,hashMode Text, checked INT)")
        cursor.execute("CREATE table infoFolders (fPath TEXT UNIQUE, userIdentiy TEXT, groupIdentity TEXT, acessRight TEXT, lastModify INT, checked INT)")
        cursor.execute("CREATE table config (hashMode TEXT)")


    @staticmethod
    def writeHash(cursor, hashType):
        cursor.execute("INSERT INTO config VALUES(?)",(hashType,))
        cursor.commit()
        print("HashMode: {}".format(hashType))


    @staticmethod
    def writeFileInfo(cursor, f, cHash):
        cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?,?,0)",(f.path,f.size,f.userIdentiy,f.groupIdentity,f.accessRight,f.lastModify,cHash))


    @staticmethod
    def writeFolderInfo(cursor, f):
        cursor.execute("INSERT INTO infoFolders VALUES(?,?,?,?,?,0)",(f.path,f.userIdentiy,f.groupIdentity,f.accessRight,f.lastModify))


    @staticmethod
    def updateInfoFolders(cursor, fPath):
        cursor.execute('UPDATE infoFolders SET checked=? WHERE fPath =?',(1,fPath))


    @staticmethod
    def updateInfoFiles(cursor, fPath):
        cursor.execute('UPDATE info SET checked=? WHERE fPath =?',(1,fPath))


    @staticmethod
    def getHashType(cursor):
        cursor = cursor.execute('SELECT * FROM config')
        for row in cursor:
            return row[0]


    @staticmethod
    def getFileInfo(cursor, filepath):
        cursor = cursor.execute('SELECT * FROM info WHERE fPath=?',(filepath,))
        for row in cursor:
            return row


    @staticmethod
    def getFolderInfo(cursor, filepath):
        cursor = cursor.execute('SELECT * FROM infoFolders WHERE fPath=?',(filepath,))
        for row in cursor:
            return row


    @staticmethod
    def getDeletedFiles(cursor):
        return cursor.execute('SELECT * FROM info WHERE checked=?',(0,))


    @staticmethod
    def getDeletedFolders(cursor):
        return cursor.execute('SELECT * FROM infoFolders WHERE checked=?',(0,))


    @staticmethod
    def updateInfoCleanup(cursor):
        # Unsure what this does. Keeping it
        cursor.execute('UPDATE info SET checked=? WHERE checked =?',(0,1)) # Changed it back
        cursor.commit()


class VerifyArgs():

    @staticmethod
    def verifyCommonInputAbortIfInvalid(args):
        VerifyArgs._monitoredDirectoryValid(args)
        VerifyArgs._inputDirNotInMetadataFiles(args.D, args.V, args.R)
        VerifyArgs._isDir(args.V, '-V')
        VerifyArgs._isDir(args.R, '-R')
        print("Verification and report ok")


    @staticmethod
    def _monitoredDirectoryValid(args):
        if not os.path.isdir(args.D):
            print("Directory {} is not existing".format(args.D))
            quit()


    @staticmethod
    def _inputDirNotInMetadataFiles(directory, verification, report):
        if directory in verification and directory in report:
            print("Verification: {}\n Report: {} \n can't be inside: " +
                "directory {}\n please specify outside {}".format(verification, report, directory, directory))
            quit()


    @staticmethod
    def _isDir(arg, f):
        if os.path.isdir(f):
            print("Argument [{}] value is not a file [{}]".format(argument, f))
            quit()


    @staticmethod
    def userChoiceYesOrNo(question):
        ans = ""
        while(ans not in ["yes", "no"]):
            ans = input(question)
        return ans


    @staticmethod
    def metadataExistUserDetermineWhatToDo(f):
        if os.path.isfile(f):
            q = "Should we overwrite file: {} yes/no : ".format(f)
            if VerifyArgs.userChoiceYesOrNo(q) == "no":
                print("We can't continue, try again with different file input")
                quit()
            else:
                os.remove(f)


    def abortMissingFile(f):
        if not os.path.isfile(f):
            print("ERROR: The file: {} is missing.".format(f))
            quit()

    def removeFile(f):
        if os.path.isfile(f):
            os.remove(f)
            print("Deleted {}".format(f))


class InitMode():

    @staticmethod
    def valid(args):
        if args.H not in ['MD-5', 'SHA-1']:
            print("You must choose a hash function either, -H SHA-1 or MD5")
            quit()

        if os.path.isfile(args.V) or os.path.isfile(args.R):
            question = "Should we overwrite verification {} and report {} yes/no : ".format(args.V, args.R)
            if VerifyArgs.userChoiceYesOrNo(question) == "no":
                print("The files will be preserved, goodbye")
                quit()
            else:
                VerifyArgs.removeFile(args.V)
                VerifyArgs.removeFile(args.R)

        VerifyArgs.metadataExistUserDetermineWhatToDo(args.V)
        VerifyArgs.metadataExistUserDetermineWhatToDo(args.R)


    @staticmethod
    def anlyseFilesToDb(folder, cursor):
        report = DiffReport()
        for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
            report.incrementDirs()
            for name in files:
                report.incrementFiles()
                filepath = os.path.join(root, name)
                cHash = getFileHash(cursor, filepath)
                DB.writeFileInfo(cursor, FileObj(filepath), cHash)

        cursor.commit()
        return report


    @staticmethod
    def anlyseFoldersToDb(folder, cursor):
        for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
            for folderName in dirs:
                folderPath = os.path.join(root, folderName)
                DB.writeFolderInfo(cursor, FileObj(folderPath))
        cursor.commit()


def getFileHash(cursor, filePath):
    hashType = DB.getHashType(cursor)
    if hashType == "MD-5":
        return _calcHash(filePath, hashlib.md5())
    elif hashType == "SHA-1":
        return _calcHash(filePath, hashlib.sha1())
    else:
        print("ERROR: Unkown hashtype {}".format(hashType))
        quit()

def _calcHash(fileName, hashObj):
    blocksize = 65536 # Reads a big chunck each time
    afile = open(fileName, 'rb') # Read file binary
    buf = afile.read(blocksize) # Read the first 65536 bytes
    while len(buf) > 0:
        hashObj.update(buf) # Att the buf to the function
        buf = afile.read(blocksize) # Large files needs iterating
    return hashObj.hexdigest() # Return the checksum


def writeReportFile(startTime, ss, fPath):
    with open(fPath, "w") as f:
        f.write(ss + getElapsedTime(startTime))

def getElapsedTime(startTime):
    return "Time to complete in seconds :" + str(time.time() - startTime) + "\n"

def initializationMode(args):
    print("Initialization mode\n")
    InitMode.valid(args)

    print("Creates new report file and verification file")
    startTime = time.time()
    cursor = DB.connect(args.V)

    DB.createTable(cursor)
    DB.writeHash(cursor, args.H)

    report = InitMode.anlyseFilesToDb(args.D, cursor)
    InitMode.anlyseFoldersToDb(args.D, cursor) # Get information about all the folders
    cursor.close() # close db connection

    ss = f"Monitored directory : {args.D}\nVerification file : {args.V}\nNr of directories : {report.dirs}\nNr of files : {report.files}\n"
    print(ss)
    writeReportFile(startTime, ss, args.R)

    print("Done with Initialization")

def isInitValid(args):
    if args.H not in ['MD-5', 'SHA-1']:
        print("You must choose a hash function either, -H SHA-1 or MD5")
        quit()

    if os.path.isfile(args.V) or os.path.isfile(args.R):
        question = "Should we overwrite verification {} and report {} yes/no : ".format(args.V, args.R)
        if VerifyArgs.userChoiceYesOrNo(question) == "no":
            print("The files will be preserved, goodbye")
            quit()
        else:
            VerifyArgs.removeFile(args.V)
            VerifyArgs.removeFile(args.R)

    VerifyArgs.metadataExistUserDetermineWhatToDo(args.V)
    VerifyArgs.metadataExistUserDetermineWhatToDo(args.R)


def verificationMode(args):
    print("Verification mode")
    isVerificationValid(args)
    ###########
    # Start verification process
    ##########
    startTime = time.time()
    cursor = DB.connect(args.V)

    filesReport = compareFiles(args.D, cursor)
    folderReport = compareFolders(args.D, cursor)
    deletedFilesReport = deletedFiles(cursor)
    deletedFolderReport = deletedFolders(cursor)

    report = filesReport + folderReport + deletedFilesReport + deletedFolderReport

    ss = f"Monitored directory : {args.D}\nVerification file : {args.V}\n{report.getSSReport()}"
    writeReportFile(startTime, ss, args.R)

    # Cleanup
    DB.updateInfoCleanup(cursor)
    print("Verification mode done")

def isVerificationValid(args):
    VerifyArgs.abortMissingFile(args.V)
    VerifyArgs.metadataExistUserDetermineWhatToDo(args.R)

def compareFiles(folder, cursor):
    diffReport = DiffReport()
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        diffReport.incrementDirs()
        for name in files:
            diffReport.incrementFiles()
            filepath = os.path.join(root, name)
            dbFileInfo = DB.getFileInfo(cursor, filepath)

            if dbFileInfo is None:
                ss = "NEW FILE: {}".format(filepath)
                print(ss)
                diffReport.incrementWarnings()
                diffReport.appendChangedFile(ss)
            else:
                # Retrive latest information about files
                cHash = getFileHash(cursor, filepath)
                errorMsg = compareWithDbFile(filepath, cHash, dbFileInfo)

                if errorMsg:
                    diffReport.incrementWarnings()
                    ssChangedFiles += errorMsg + "\n"

                DB.updateInfoFiles(cursor, filepath)
        cursor.commit()

    return diffReport

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

def compareFolders(folder, cursor):
    diffReport = DiffReport()
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        for name in dirs:
            itemChanged = False
            fPath = os.path.join(root, name)
            oldInfo = DB.getFolderInfo(cursor, fPath)

            if oldInfo == None:
                ss = "NEW FOLDER: {}".format(fPath)
                print(ss)
                diffReport.incrementWarnings()
                diffReport.appendChangedFile(ss)
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
                    ss = errorMsg + "\n"
                    print(ss)
                    diffReport.incrementWarnings()
                    diffReport.appendChangedFile(ss)

                DB.updateInfoFolders(cursor, fPath)
        cursor.commit()

    return diffReport

def deletedFiles(cursor):
    cursor = DB.getDeletedFiles(cursor)
    return _deletedPaths('File', cursor)

def deletedFolders(cursor):
    cursor = DB.getDeletedFolders(cursor)
    return _deletedPaths('Folder', cursor)

def _deletedPaths(mode, rows):
    report = DiffReport()
    for row in rows:
        ss = f"{mode} deleted: {row[0]}"
        print(ss)
        report.incrementWarnings()
        report.appendChangedFile(ss)
    return report


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
    VerifyArgs.verifyCommonInputAbortIfInvalid(args)
    if args.i:
        initializationMode(args)
    elif args.v:
        verificationMode(args)

if __name__ == "__main__":
    main()
