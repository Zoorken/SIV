#!/usr/bin/python3
import argparse, os, stat, sqlite3, time, hashlib, csv
from pwd import getpwuid

def connect_db(filepath):
    print(filepath)
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


def getFileInfo(folder, cursor, hashType):
    nrOfDirs = 0
    nrOfFiles = 0
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        nrOfDirs += 1
        for name in files:
            nrOfFiles +=1
            filepath = os.path.join(root, name)
            st = os.stat(filepath)
            acessRight = oct(stat.S_IMODE(st.st_mode)) # wwww.stomp.colorado.edu
            fileSize = st.st_size
            userIdentiy = getpwuid(st.st_uid).pw_name
            groupIdentity = getpwuid(st.st_gid).pw_name
            lastModify = st.st_mtime

            # Should calculate some hashing
            if(hashType == "MD-5"):
                md5 = hashlib.md5()
                cHash = calcHash(filepath, md5)
            else:
                sha1 = hashlib.sha1()
                cHash = calcHash(filepath, sha1)

            cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?,?,0)",(filepath,fileSize,userIdentiy,groupIdentity,acessRight,lastModify,cHash))

    cursor.commit()
    return (nrOfDirs, nrOfFiles)

def getFolderInfo(folder, cursor):
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        for folderName in dirs:
            folderPath = os.path.join(root,folderName)
            folderSt = os.stat(folderPath)
            acessRight = oct(stat.S_IMODE(folderSt.st_mode))
            userIdentiy = getpwuid(folderSt.st_uid).pw_name
            groupIdentity = getpwuid(folderSt.st_gid).pw_name
            lastModify = folderSt.st_mtime

            cursor.execute("INSERT INTO infoFolders VALUES(?,?,?,?,?,0)",(folderPath,userIdentiy,groupIdentity,acessRight,lastModify))
    cursor.commit()


def calcHash(fileName, hashObj):
    blocksize = 65536 # Reads a big chunck each time
    afile = open(fileName, 'rb') # Read file binary
    buf = afile.read(blocksize) # Read the first 65536 bytes
    while len(buf) > 0:
        hashObj.update(buf) # Att the buf to the function
        buf = afile.read(blocksize) # Large files needs iterating
    return hashObj.hexdigest() # Return the checksum


def getOldfileInfo(cursor,filepath):
    cursor = cursor.execute('SELECT * FROM info WHERE fPath=?',(filepath,))
    for row in cursor:
        return row

def getOldFolderInfo(cursor,filepath):
    cursor = cursor.execute('SELECT * FROM infoFolders WHERE fPath=?',(filepath,))
    for row in cursor:
        return row

def getHashTypeInfo(cursor):
    cursor = cursor.execute('SELECT * FROM config')
    for row in cursor:
        return row[0]


def initializationReport(monitoreDirectory, pathVerification, nrOfDir, nrofFiles, startTime, reportFile):
    ss = "Monitored directory :" + monitoreDirectory + "\n" + "Verification file :" + pathVerification + "\n" + "Nr of directorys :" + str(nrOfDir) + "\n" + "Nr of files :" + str(nrofFiles) + "\n"
    fprint = open(reportFile,"w")
    elapsedTime = time.time() - startTime
    ss += "Time to complete in seconds :" + str(elapsedTime) + "\n"
    fprint.write(ss)
    fprint.close()


def initializationMode(args):
    print("Initialization mode\n")
    if(os.path.isdir(args.D)): # Check if directory exist
        print("{} exists".format(args.D))
        if args.D not in args.V and args.D not in args.R: # Check if the paths is outside the directory
            if os.path.isdir(args.V) or os.path.isdir(args.R):
                print("Need to specify a file for verification file and report file")
                quit()

            print("Verification and report ok")
            # check if verification and report file exists
            if args.H == "MD-5" or args.H == "SHA-1":
                if os.path.isfile(args.V) or os.path.isfile(args.R):
                    # User must do a choice
                    string = "Should we overwrite verification {} and report {} yes/no : ".format(args.V, args.R)
                    if userChoiceDeleteVerandReport(args, string) == "no":
                        print("The files will be preserved, goodbye")
                        quit() # terminate the program
                    else:
                        if os.path.isfile(args.V):
                            os.remove(args.V)
                        if os.path.isfile(args.R):
                            os.remove(args.R)
                # Continue if this was the users will
                print("Creates new report file and verification file")
                startTime = time.time()

                cursor = dbCreateTable(args.V)
                sethashTypeDB(cursor, args.H) # Now we have stored which type hash is

                nrOfDirs, nrOfFiles = getFileInfo(args.D, cursor, args.H)
                getFolderInfo(args.D, cursor) # Get information about all the folders
                cursor.close() # close db connection
                initializationReport(args.D, args.V, nrOfDirs, nrOfFiles, startTime, args.R)
                print("Done with Initialization")
            else:
                print("You must choose a hash function either, -H SHA-1 or MD5")
        else:
            print("Verification: {}\n Report: {} \n can't be inside: directory {}\n please specify outside {}".format(args.V, args.R, args.D, args.D))
    else: #isdir args.D
        print("Directory {} is not existing".format(args.D))



def verificationMode(args):
    print("Verification mode")
    # Checking users input
    if checkUserInputIfValid(args):
        if os.path.isfile(args.V): # Make sure the verification and report exists
            if os.path.isfile(args.R):
                string = "Should we overwrite report {} yes/no : ".format(args.R)
                if userChoiceDeleteVerandReport(args, string) == "no":
                    print("We can't continue, try again with different report file")
                    quit()
                else:
                    os.remove(args.R)
            ###########
            # Start verification process
            ##########
            startTime = time.time()
            cursor = connect_db(args.V)
            hashType = getHashTypeInfo(cursor)
            print(hashType)
            nrOfWarnings, nrOfDirs, nrOfFiles, ssChangedFiles = compare(args.D, cursor, hashType)
            nrOfWarnings, ssChangedFiles = compareFolders(args.D, cursor, nrOfWarnings)
            nrOfWarnings, ssChangedFiles = deletedFiles(cursor, nrOfWarnings, ssChangedFiles)
            nrOfWarnings, ssChangedFiles = deletedFolders(cursor, nrOfWarnings, ssChangedFiles)

            reportFileVerification(args.D, args.V, args.R, nrOfDirs, nrOfFiles, nrOfWarnings,startTime, ssChangedFiles)
            # Clean up
            cursor.execute('UPDATE info SET checked=? WHERE checked =?',(0,1)) # Changed it back
            cursor.commit() # Change it back
        else:
            print("Verification db don't exists")

    else: # checkUserInputIfValid
        quit()

def compare(folder, cursor, hashType):
    fileChanged = False
    nrOfDirs = 0
    nrOfFiles = 0
    nrOfWarnings = 0
    ssChangedFiles = ""
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        nrOfDirs += 1
        for name in files:
            nrOfFiles += 1
            fileChanged = False
            filepath = os.path.join(root, name)
            oldInfo = getOldfileInfo(cursor,filepath)
            if oldInfo == None:
                nrOfWarnings +=1
                print("NEW FILE: {}".format(filepath))
                ssChangedFiles += "NEW FILE: {}\n".format(filepath)
            else:
                # Retrive latest information about files
                st = os.stat(filepath)
                acessRight = oct(stat.S_IMODE(st.st_mode)) #wwww.stomp.colorado.edu
                fileSize = st.st_size
                userIdentiy = getpwuid(st.st_uid).pw_name
                groupIdentity = getpwuid(st.st_gid).pw_name
                lastModify = st.st_mtime

                # Should calculate some hashing
                if(hashType == "MD-5"):
                    md5 = hashlib.md5()
                    cHash = calcHash(filepath, md5)
                else:
                    sha1 = hashlib.sha1()
                    cHash = calcHash(filepath, sha1)

                #Compare the files with the one in db
                errorMsg = "CHANGED: File {} ".format(filepath)
                if oldInfo[5] != lastModify:
                    fileChanged = True
                    errorMsg += ", prev changes where made {} new changes {}".format(oldInfo[5], lastModify)
                    # File has been modified from db version
                if oldInfo[1] != int(fileSize):
                    fileChanged = True
                    errorMsg += ", fileSize from {} to {}".format(oldInfo[1],fileSize)
                if oldInfo[2] != userIdentiy:
                    fileChanged = True
                    errorMsg += ", useridentify from {} to {}".format(oldInfo[2], userIdentiy)
                if oldInfo[3] != groupIdentity:
                    fileChanged = True
                    errorMsg += ", groupidentiy from {} to {}".format(oldInfo[3], groupIdentity)
                if oldInfo[4] != str(acessRight):
                    fileChanged = True
                    errorMsg += ", accessright from {} to {}".format(oldInfo[4], acessRight)
                if oldInfo[6] != cHash:
                    fileChanged = True
                    errorMsg += ", file content compromized, hash not same"

                if fileChanged:
                    nrOfWarnings +=1
                    print(errorMsg + "\n")
                    ssChangedFiles += errorMsg + "\n"

                cursor.execute('UPDATE info SET checked=? WHERE fPath =?',(1,filepath))
        cursor.commit()

    return (nrOfWarnings,nrOfDirs,nrOfFiles,ssChangedFiles)

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

def reportFileVerification(monitoreDirectory, pathVerification, reportFile, nrOfDir, nrOfFiles, nrOfWarnings, startTime, ssChangedFiles):
    ss = "Monitored directory: " + os.path.abspath(monitoreDirectory) + "\nVerification file: " + os.path.abspath(pathVerification) + "\nReport file: "+ os.path.abspath(reportFile) + "\nNr of directorys: " + str(nrOfDir) + "\nNr of files: " + str(nrOfFiles) + "\nNr of warnings: " + str(nrOfWarnings)
    fprint = open(reportFile,"w")
    elapsedTime = time.time() - startTime
    ss += "\nTime to complete in seconds: " + str(int(round(elapsedTime))) + "\n"
    ss += ssChangedFiles
    fprint.write(ss)
    fprint.close()


def removeFiles(args):
    if os.path.isfile(args.V) and os.path.isfile(args.R):
        os.remove(args.V)
        os.path.isfile(args.R)
    else:
        print("Error occured while removing {} and {},\n The program will exit".format(args.V, args.R))
        quit()

def userChoiceDeleteVerandReport(args, string):
    ans = ""
    while(ans != "yes" and ans != "no"):
        ans = input(string)
    return ans


def checkUserInputIfValid(args):
    flag = False
    if(os.path.isdir(args.D)): # Check if directory exist
        #print("{} exists".format(args.D))
        if args.D not in args.V and args.D not in args.R: # Check if the paths is outside the directory
            if os.path.isdir(args.V) or os.path.isdir(args.R): # Check that the paths not leads to folders
                print("Need to specify a file for verification and report")
            else:
                print("Verification and report ok")
                flag = True
        else:
            print("Verification: {}\n Report: {} \n can't be inside: directory {}\n please specify outside {}".format(args.V, args.R, args.D, args.D))
    else: #isdir args.D
        print("Directory {} is not existing".format(args.D))

    return flag

def argumentParser():
    parser = argparse.ArgumentParser(description="Use the program in either Initialization or Verification mode:\n Example Initialization: siv -i -D important_directory -V verificationDB -R my_repoirt.txt -H sha1\n Example Verification: siv -v -D important_directory -V verificationDB -R my_report2.txt")
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
    if args.i:
        initializationMode(args)
    elif args.v:
        verificationMode(args)

if __name__ == "__main__":
    main()
