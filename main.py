#!/usr/bin/python3
import argparse, os, stat, sqlite3, time, hashlib, csv
from pwd import getpwuid


class FileObj:
    def __init__(self):
        self.path = None
        self.st = None
        self.accessRight = None
        self.size = None
        self.userIdentiy = None
        self.groupIdentity = None
        self.lastModify = None
        self.cHash = ""

    def initFromDB(self, db):
        self.path = db[0]
        self.userIdentiy = db[1]
        self.groupIdentity = db[2]
        self.accessRight = db[3]
        self.lastModify = db[4]
        self.size = db[5]
        if len(db) > 7:
            self.cHash = db[6]
        return self

    def initFromFilepath(self, path):
        self.path = path
        self.st = self.setOsStat()
        self.accessRight = self.setAccessRight()
        self.size = self.setSize()
        self.userIdentiy = self.setUserIdentiy()
        self.groupIdentity = self.setGroupIdentity()
        self.lastModify = self.setLastModify()
        return self

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

    def setChash(self, cHash):
        self.cHash = cHash
        return self

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
        cursor.execute("CREATE table info (fPath TEXT UNIQUE, userIdentidy TEXT, groupIdentity Text, acessRight Text, lastModify INT,fileSize INT,hash Text, checked INT)")
        cursor.execute("CREATE table infoFolders (fPath TEXT UNIQUE, userIdentiy TEXT, groupIdentity TEXT, acessRight TEXT, lastModify INT, checked INT)")
        cursor.execute("CREATE table config (hashMode TEXT)")

    @staticmethod
    def writeHash(cursor, hashType):
        cursor.execute("INSERT INTO config VALUES(?)",(hashType,))
        cursor.commit()
        print("HashMode: {}".format(hashType))

    @staticmethod
    def writeFileInfo(cursor, f):
        cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?,?,0)",(f.path,f.userIdentiy,f.groupIdentity,f.accessRight,f.lastModify,f.size,f.cHash))

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
        row = DB._getFileInfo(cursor, filepath)
        if row:
            Utils.loggPrinter(f"DB file row {row}")
            return FileObj().initFromDB(row)
        return row

    @staticmethod
    def _getFileInfo(cursor, filepath):
        cursor = cursor.execute('SELECT * FROM info WHERE fPath=?',(filepath,))
        for row in cursor:
            return row

    @staticmethod
    def getFolderInfo(cursor, filepath):
        row = DB._getFolderInfo(cursor, filepath)
        if row:
            Utils.loggPrinter(f"DB folder row {row}")
            return FileObj().initFromDB(row)
        return row

    @staticmethod
    def _getFolderInfo(cursor, filepath):
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


class VerifyArgs:

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
    def _isDir(inputArgument, f):
        if os.path.isdir(f):
            print("Argument [{}] value is not a file [{}]".format(inputArgument, f))
            quit()

    @staticmethod
    def userChoiceYesOrNo(question):
        ans = ""
        while ans not in ["yes", "no"]:
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


class InitMode:

    @staticmethod
    def start(args):
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
        Utils.writeReportFile(startTime, ss, args.R)

        print("Done with Initialization")

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
                cHash = Utils.getFileHash(DB.getHashType(cursor), filepath)
                DB.writeFileInfo(cursor, FileObj().initFromFilepath(filepath).setChash(cHash))

        cursor.commit()
        return report

    @staticmethod
    def anlyseFoldersToDb(folder, cursor):
        for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
            for folderName in dirs:
                folderPath = os.path.join(root, folderName)
                DB.writeFolderInfo(cursor, FileObj().initFromFilepath(folderPath))
        cursor.commit()


class Verification:

    @staticmethod
    def start(args):
        print("Verification")
        Verification.inputValid(args)


        startTime = time.time()
        cursor = DB.connect(args.V)

        report  = Verification.generateReport(cursor, args.D, args.V)
        Utils.writeReportFile(startTime, report, args.R)

        # Cleanup
        DB.updateInfoCleanup(cursor)
        print("Verification mode done")

    @staticmethod
    def inputValid(args):
        VerifyArgs.abortMissingFile(args.V)
        VerifyArgs.metadataExistUserDetermineWhatToDo(args.R)

    @staticmethod
    def generateReport(cursor, dir, verF):
        filesReport = Compare.files(cursor, dir)
        folderReport = Compare.folders(cursor, dir)
        deletedFilesReport = Verification.deletedFiles(cursor)
        deletedFolderReport = Verification.deletedFolders(cursor)

        report = filesReport + folderReport + deletedFilesReport + deletedFolderReport
        return f"Monitored directory : {dir}\nVerification file : {verF}\n{report.getSSReport()}"

    @staticmethod
    def deletedFiles(cursor):
        cursor = DB.getDeletedFiles(cursor)
        return Verification._deletedPaths('File', cursor)

    @staticmethod
    def deletedFolders(cursor):
        cursor = DB.getDeletedFolders(cursor)
        return Verification._deletedPaths('Folder', cursor)

    @staticmethod
    def _deletedPaths(mode, rows):
        report = DiffReport()
        for row in rows:
            ss = f"{mode} deleted: {row[0]}"
            print(ss)
            report.incrementWarnings()
            report.appendChangedFile(ss)
        return report


class Compare:

    @staticmethod
    def files(cursor, folder):
        diffReport = DiffReport()
        for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
            diffReport.incrementDirs()
            for name in files:
                diffReport.incrementFiles()
                filepath = os.path.join(root, name)
                diffReport + Compare._filesAndFolder(cursor, filepath, 'FILE')
            cursor.commit()
        return diffReport

    @staticmethod
    def folders(cursor, folder):
        diffReport = DiffReport()
        for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
            for name in dirs:
                filepath = os.path.join(root, name)
                diffReport += Compare._filesAndFolder(cursor, filepath, 'FOLDER')
            cursor.commit()

        return diffReport

    @staticmethod
    def _filesAndFolder(cursor, filepath, mode):
        if mode == 'FILE':
            dbFileObj = DB.getFileInfo(cursor, filepath)
        elif mode == 'FOLDER':
            dbFileObj = DB.getFolderInfo(cursor, filepath)
        else:
            print(f"ERROR mode {mode}")
            quit()

        diffReport = DiffReport()
        if dbFileObj is None:
            ss = f"NEW {mode}: {filepath}"
            print(ss)
            diffReport.incrementWarnings()
            diffReport.appendChangedFile(ss)
        else:
            print(f"This is from db {dbFileObj.accessRight} {mode}")
            if mode == 'FILE':
                cHash = Utils.getFileHash(DB.getHashType(cursor), filepath)
                errorMsg = Compare._withDbFile(filepath, cHash, dbFileObj)
            elif mode == 'FOLDER':
                errorMsg = Compare._withDbFolder(filepath, dbFileObj)

            if errorMsg:
                errorMsg += "\n"
                print(errorMsg)
                diffReport.incrementWarnings()
                diffReport.appendChangedFile(errorMsg)

            DB.updateInfoFiles(cursor, filepath)
        return diffReport

    @staticmethod
    def _withDbFile(filepath, cHash, dbObj):
        fileObj = FileObj().initFromFilepath(filepath).setChash(cHash)
        eMsg = ''

        eMsg += Compare._userIdentity(dbObj.userIdentiy, fileObj.userIdentiy)
        eMsg += Compare._groupIdentity(dbObj.groupIdentity, fileObj.groupIdentity)
        eMsg += Compare._accessRight(dbObj.accessRight, fileObj.accessRight)
        eMsg += Compare._lastModify(dbObj.lastModify, fileObj.lastModify)

        if dbObj.getSizeInInt() != fileObj.getSizeInInt():
            eMsg += ", fileSize from {} to {}".format(dbObj.getSizeInInt(),
                                                      fileObj.getSizeInInt())

        if dbObj.cHash != fileObj.cHash:
            Utils.loggPrinter(f"dbHash: {dbObj.cHash}. fHash {fileObj.cHash}\n")
            eMsg += ", file content compromised, hash differ"

        if eMsg:
            eMsg = "CHANGED: File {} ".format(fileObj.path) + eMsg

        return eMsg

    @staticmethod
    def _withDbFolder(filepath, dbObj):
        fileObj = FileObj().initFromFilepath(filepath)
        eMsg = ''

        eMsg += Compare._userIdentity(dbObj.userIdentiy, fileObj.userIdentiy)
        eMsg += Compare._groupIdentity(dbObj.groupIdentity, fileObj.groupIdentity)
        eMsg += Compare._accessRight(dbObj.accessRight, fileObj.accessRight)
        eMsg += Compare._lastModify(dbObj.lastModify, fileObj.lastModify)

        if eMsg:
            eMsg = "CHANGED: Folder {} ".format(fileObj.path) + eMsg

        return eMsg

    @staticmethod
    def _lastModify(dbFModify, fLastModify):
        eMsg = ''
        if dbFModify != fLastModify:
            eMsg = f", prev changes where made {dbFModify} new changes {fLastModify}"
        return eMsg

    @staticmethod
    def _accessRight(dbFAccessRight, fAccessRight):
        eMsg = ''
        if dbFAccessRight != str(fAccessRight):
            eMsg = f", accessright from {dbFAccessRight} to {fAccessRight}"
        return eMsg

    @staticmethod
    def _groupIdentity(dbFGroupIdentity, fGroupIdentity):
        eMsg = ''
        if dbFGroupIdentity != fGroupIdentity:
            eMsg = f", groupidentiy from {dbFGroupIdentity} to {fGroupIdentity}"
        return eMsg

    @staticmethod
    def _userIdentity(dbFUserIdentity, fUserIdentity):
        eMsg = ''
        if dbFUserIdentity != fUserIdentity:
            eMsg = f", useridentify from {dbFUserIdentity} to {fUserIdentity}"
        return eMsg


class Utils:

    @staticmethod
    def getFileHash(hashType, filePath):
        if hashType == "MD-5":
            return Utils._calcHash(filePath, hashlib.md5())
        elif hashType == "SHA-1":
            return Utils._calcHash(filePath, hashlib.sha1())
        else:
            print(f"ERROR: Unkown hashtype {hashType}")
            quit()

    @staticmethod
    def _calcHash(fileName, hashObj):
        blocksize = 65536 # Reads a big chunck each time
        afile = open(fileName, 'rb') # Read file binary
        buf = afile.read(blocksize) # Read the first 65536 bytes
        while len(buf) > 0:
            hashObj.update(buf) # Att the buf to the function
            buf = afile.read(blocksize) # Large files needs iterating
        return hashObj.hexdigest() # Return the checksum

    @staticmethod
    def writeReportFile(startTime, ss, fPath):
        with open(fPath, "w") as f:
            f.write(ss + Utils.getElapsedTime(startTime))

    @staticmethod
    def getElapsedTime(startTime):
        return "Time to complete in seconds :" + str(time.time() - startTime) + "\n"

    @staticmethod
    def loggPrinter(ss):
        return ""
        #print(ss)


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
        InitMode.start(args)
    elif args.v:
        Verification.start(args)


if __name__ == "__main__":
    main()
