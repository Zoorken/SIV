import os

for root, dirs, files in os.walk(os.path.abspath("/Users/Fredrik/SIV/test"), topdown=True):
    for name in files:
        # pathway to file os.path.join(root, name)
        st = os.stat(os.path.join(root, name))
        print(st)


    #for name in dirs:
    #    print(os.path.join(root, name))
