import os, stat, sqlite3
from pwd import getpwuid

def connect_db():
    return sqlite3.connect('test.db')

def dbCreateTable():
    cursor = connect_db()
    cursor.execute("CREATE table info (filePath TEXT UNIQUE, fileSize INT, userIdentidy TEXT, groupIdentity Text, acessRight Text, lastModify INT)")

def getFileInfo(folder, cursor):
    for root, dirs, files in os.walk(os.path.abspath(folder), topdown=True):
        for name in files:
            filepath = os.path.join(root, name)
            #st = os.stat(filepath)
            st = os.stat(filepath)
            #acessRight = st.st_mode #Give the python value need to convert
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

            # Should use a flag like "been verifed" == 0 and then when im comparing and goes to the one i mark it as 1 and
            # at the end of the comparingsion do a sqlite call to check which files has been checked. Otherwise I won't notice
            # the file that was in the file system befor 
            #cursor.execute("INSERT INTO info VALUES(?,?,?,?,?,?)",(filepath,fileSize,userIdentiy,groupIdentity,acessRight,lastModify))
            #cursor.commit()
            #getOldfileInfo(cursor,filepath)
            compare(cursor, filepath, lastModify, fileSize, userIdentiy, groupIdentity, acessRight)

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
#dbCreateTable()

cursor = connect_db()
getFileInfo("/home/fredrik/SIV/test", cursor)
#getDBFileInfo(cursor)
cursor.close()
