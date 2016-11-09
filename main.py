#!/usr/bin/python3
import argparse, os, stat, sqlite3, time
from pwd import getpwuid

def argumentParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help="Initialization mode", action="store_true")
    parser.add_argument("-v", help="Verification mode", action="store_true")
    parser.add_argument("-D", help="Monitored directory")
    parser.add_argument("-V", help="Verification file, not in monitored directory")
    parser.add_argument("-R", help="Report file, not in monitored directory")
    parser.add_argument("-H", help="Hash function", choices=["SHA-1", "MD-5"])
    return parser.parse_args()


def connect_db(filepath):
    print(filepath)
    return sqlite3.connect(filepath)


def dbCreateTable(filepath):
    cursor = connect_db(filepath)
    cursor.execute("CREATE table info (filePath TEXT UNIQUE, fileSize INT, userIdentidy TEXT, groupIdentity Text, acessRight Text, lastModify INT, checked Int)")
    return cursor


def getFileInfo(folder, cursor):
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        for name in files:
            filepath = os.path.join(root, name)
            st = os.stat(filepath)
            acessRight = oct(stat.S_IMODE(st.st_mode)) #wwww.stomp.colorado.edu
            fileSize = st.st_size
            userIdentiy = getpwuid(st.st_uid).pw_name
            groupIdentity = getpwuid(st.st_gid).pw_name
            lastModify = st.st_mtime

            print("Filepath {}".format(filepath))
            print("Filesize {}".format(fileSize))
            print("OwnerIdentidy {}".format(userIdentiy))
            print("GroupIdentify {}".format(groupIdentity))
            print("AccessRight {}".format(acessRight))
            print("lastModify {}".format(lastModify))

            # Should calculate some hashing

            cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?,0)",(filepath,fileSize,userIdentiy,groupIdentity,acessRight,lastModify))
            cursor.commit()
            #compare(cursor, filepath, lastModify, fileSize, userIdentiy, groupIdentity, acessRight)


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
        else:
            # File has not been changed since befor
            print("Hej")


def initializationReport(monitoreDirectory, pathVerification, nrOfDir, nrofFiles, startTime, reportFile):
    ss = monitoreDirectory + "\n" + pathVerification + "\n" + nrOfDir + "\n" + nrofFiles + "\n"
    fprint = open(reportFile,"wb")
    endTime = time.time()
    elapsedTime = endTime - startTime
    ss += elapsedTime + "\n"
    fprint.write(ss)
    fprint.close()


def initializationMode(args):
    print("Initialization mode\n")
    if args.D: # Check if user provided argument
        if(os.path.isdir(args.D)): # Check if directory exist
            print("{} exists".format(args.D))
            if args.V and args.R: # Check if user provided verification and report argument
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
                    cursor = dbCreateTable(args.V)
                    getFileInfo(args.D, cursor)
                    cursor.close()
                else:
                    print("Verification: {}\n Report: {} \n can't be inside: directory {}\n please specify outside {}".format(args.V, args.R, args.D, args.D))
            else: # args.V && R is provided
                print("Specify verification file and Report file")
        else: #isdir args.D
            print("Directory {} is not existing".format(args.D))
    else: # args.D
        print("Specify monitored directory\n")


def verificationMode(args):
    print("Verification mode")


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
