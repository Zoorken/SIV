#!/usr/bin/python3
import argparse, os, stat, sqlite3, time, hashlib, csv
from pwd import getpwuid

def argumentParser():
    parser = argparse.ArgumentParser(description="Use the program in either Initialization or Verification mode:\n Example Initialization: siv -i -D important_directory -V verificationDB -R my_repoirt.txt -H sha1\n Example Verification: siv -v -D important_directory -V verificationDB -R my_report2.txt")
    parser.add_argument("-i", help="Initialization mode", action="store_true")
    parser.add_argument("-v", help="Verification mode", action="store_true")
    parser.add_argument("-D", help="Monitored directory", required=True)
    parser.add_argument("-V", help="Verification file, not in monitored directory", required=True)
    parser.add_argument("-R", help="Report file, not in monitored directory", required=True)
    parser.add_argument("-H", help="Hash function", choices=["SHA-1", "MD-5"])
    return parser.parse_args()


def connect_db(filepath):
    print(filepath)
    return sqlite3.connect(filepath)


def dbCreateTable(filepath, hashMode):
    cursor = connect_db(filepath)
    cursor.execute("CREATE table info (filePath TEXT UNIQUE, fileSize INT, userIdentidy TEXT, groupIdentity Text, acessRight Text, lastModify INT, " + hashMode +" Text, checked Int)")
    return cursor


def getFileInfo(folder, cursor):
    nrOfDirs = 0
    nrOfFiles = 0
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        nrOfDirs += 1
        for name in files:
            nrOfFiles +=1
            filepath = os.path.join(root, name)
            st = os.stat(filepath)
            acessRight = oct(stat.S_IMODE(st.st_mode)) #wwww.stomp.colorado.edu
            fileSize = st.st_size
            userIdentiy = getpwuid(st.st_uid).pw_name
            groupIdentity = getpwuid(st.st_gid).pw_name
            lastModify = st.st_mtime

            # Should calculate some hashing
            md5Hash = md5(filepath)

            cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?,?,0)",(filepath,fileSize,userIdentiy,groupIdentity,acessRight,lastModify,md5Hash))

            #compare(cursor, filepath, lastModify, fileSize, userIdentiy, groupIdentity, acessRight)


    cursor.commit()
    return (nrOfDirs, nrOfFiles)


def md5(fileName):
    md5 = hashlib.md5() # Create md5 object
    blocksize = 65536 # Reads a big chunck each time
    afile = open(fileName, 'rb') # Read file binary
    buf = afile.read(blocksize) # Read the first 65536 bytes
    while len(buf) > 0:
        md5.update(buf) # Att the buf to the function
        buf = afile.read(blocksize) # Large files needs iterating
    return md5.hexdigest() # Return the checksum


def getOldfileInfo(cursor,filepath):
    cursor = cursor.execute('SELECT * FROM info WHERE filepath=?',(filepath,))
    for row in cursor:
        return row


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
                    ans = ""
                    while(ans != "yes" and ans != "no"):
                        ans = input("Should we overwrite verification {} and report {} yes/no : ".format(args.V, args.R))
                    if ans == "no":
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

                if args.H == "MD-5": # Determine the name of the field in db
                    cursor = dbCreateTable(args.V,"md5")
                else:
                    cursor = dbCreateTable(args.V,"sha1")

                nrOfDirs, nrOfFiles = getFileInfo(args.D, cursor)
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
        if os.path.isfile(args.V) and os.path.isfile(args.R): # Make sure the verification and report exists
            ###########
            # Start verification process
            ##########
            startTime = time.time()
            cursor = connect_db(args.V)
            nrOfWarnings, nrOfDirs, nrOfFiles, ssChangedFiles= compare(args.D, cursor)
            nrOfWarnings, ssChangedFiles = deletedFiles(cursor, nrOfWarnings, ssChangedFiles)

            reportFileVerification(args.D, args.V, args.R, nrOfDirs, nrOfFiles, nrOfWarnings,startTime, ssChangedFiles)
            # Clean up
            cursor.execute('UPDATE info SET checked=? WHERE checked =?',(0,1)) # Changed it back
            cursor.commit() # Change it back

    else: # checkUserInputIfValid
        quit()

def compare(folder, cursor):
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
                md5Hash = md5(filepath)

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

                if fileChanged:
                    nrOfWarnings +=1
                    print(errorMsg + "\n")
                    ssChangedFiles += errorMsg + "\n"

                cursor.execute('UPDATE info SET checked=? WHERE filepath =?',(1,filepath))
        cursor.commit()

    return (nrOfWarnings,nrOfDirs,nrOfFiles,ssChangedFiles)

def deletedFiles(cursor, nrOfWarnings, ssChangedFiles):
    cursor = cursor.execute('SELECT * FROM info WHERE checked=?',(0,))
    for row in cursor:
        nrOfWarnings += 1
        print("File been deleted: {}".format(row))
        ssChangedFiles += "File been deleted: {}\n".format(row)

    return (nrOfWarnings, ssChangedFiles)

def reportFileVerification(monitoreDirectory, pathVerification, reportFile, nrOfDir, nrOfFiles, nrOfWarnings, startTime, ssChangedFiles):
    ss = "Monitored directory: " + monitoreDirectory + "\nVerification file: " + pathVerification + "\nReport file: "+ reportFile + "\nNr of directorys: " + str(nrOfDir) + "\nNr of files: " + str(nrOfFiles) + "\nNr of warnings: " + str(nrOfWarnings)
    fprint = open(reportFile,"w")
    elapsedTime = time.time() - startTime
    ss += "\nTime to complete in seconds: " + str(elapsedTime) + "\n"
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


def userChoiceDeleteVerandReport(args):
    ans = ""
    while(ans != "yes" and ans != "no"):
        ans = input("Should we overwrite verification {} and report {} yes/no : ".format(args.V, args.R))
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



def main():
    args = argumentParser()
    if args.i:
        initializationMode(args)
    elif args.v:
        verificationMode(args)
    else:
        print("Error, need to choose Initialization or verification, 'python3 main.py -h' for help")


if __name__ == "__main__":
    main()
