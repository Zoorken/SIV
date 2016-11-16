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

            #print("Filepath {}".format(filepath))
            #print("Filesize {}".format(fileSize))
            #print("OwnerIdentidy {}".format(userIdentiy))
            #print("GroupIdentify {}".format(groupIdentity))
            #print("AccessRight {}".format(acessRight))
            #print("lastModify {}".format(lastModify))
            # Should calculate some hashing
            md5Hash = md5(filepath)

            cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?,?,0)",(filepath,fileSize,userIdentiy,groupIdentity,acessRight,lastModify,md5Hash))
    cursor.commit()
            #compare(cursor, filepath, lastModify, fileSize, userIdentiy, groupIdentity, acessRight)
    #return {'nrOfDirs':nrOfDirs, 'nrOfFiles':nrOfFiles }
    #yield nrOfDirs # first time the function is called it return dirs, the function stops here
    #yield nrOfFiles # Second time the function is called it return nrOfFiles
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


def compare(cursor, filepath, lastModify, fileSize, userIdentiy, groupIdentity, acessRight):
    errorMsg = "*********CHANGED: File {}***********\n".format(filepath)
    oldInfo = getOldfileInfo(cursor,filepath)
    if oldInfo == None:
        # There is no reccord of this file in db
        print("NEW FILE found: {}".format(filepath))
    else:
        # update that the file is going to be checked
        cursor.execute('UPDATE info SET checked=? WHERE filepath = ?',(1,filepath))
        ursor.commit()
        # file exists in db
        print("File is in db") # debugger
        if oldInfo[5] != lastModify:
            errorMsg += "prev changes where made {} new changes {}\n".format(oldInfo[5], lastModify)
            # File has been modified from db version
            if oldInfo[1] != int(fileSize):
                errorMsg += "changed fileSize from {} to {}\n".format(oldInfo[1],fileSize)
            if oldInfo[2] != userIdentiy:
                errorMsg += "changed useridentify from {} to {}\n".format(oldInfo[2], userIdentiy)
            if oldInfo[3] != groupIdentity:
                errorMsg += "changed groupidentiy from {} to {}\n".format(oldInfo[3], groupIdentity)
            if oldInfo[4] != str(acessRight):
                errorMsg += "changed accessright from {} to {}\n".format(oldInfo[4], acessRight)

            print(errorMsg)
        #else:
            # File has not been changed since befor


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
            print("Will create new files")
            startTime = time.time()

            if args.H == "MD-5": # Determine the name of the field in db
                cursor = dbCreateTable(args.V,"md5")
            else:
                cursor = dbCreateTable(args.V,"sha1")

            nrOfDirs, nrOfFiles = getFileInfo(args.D, cursor)
            cursor.close() # close db connection
            initializationReport(args.D, args.V, nrOfDirs, nrOfFiles, startTime, args.R)
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
            print("Start verification process")
            mDirectory, verDB = parseReportFile(args)

    else: # checkUserInputIfValid
        quit()

def parseReportFile(args):
    reportInformation = []
    print("Begin parsing")
    with open(args.R, newline='') as csvfile:
        parser = csv.reader(csvfile, delimiter=':')
        for row in parser:
            reportInformation.append(row[1])
    # This information should be enought for now
    return (reportInformation[0], reportInformation[1])

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
            if os.path.isdir(args.V) or os.path.isdir(args.R): # Check that the paths leads to folders
                print("Need to specify a file for verification file and report file")
            else:
                print("Verification and report ok")
                flag = True
                # check if verification and report file exists
                #if os.path.isfile(args.V) or os.path.isfile(args.R):
                    # User must do a choice
                #    if userChoiceDeleteVerandReport == "no":
                #        print("The files will be preserved, goodbye")
                #        quit() # terminate the program
                #    else:
                #        removeFiles(args)
                # Continue if this was the users will
                #print("Will create new files")
                #startTime = time.time()

                #if args.H == "MD-5": # Determine the name of the field in db
                #    cursor = dbCreateTable(args.V,"md5")
                #else:
                #    cursor = dbCreateTable(args.V,"sha1")
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
