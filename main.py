#!/usr/bin/python3
import argparse, os

def argumentParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help="Initialization mode", action="store_true")
    parser.add_argument("-v", help="Verification mode", action="store_true")
    parser.add_argument("-D", help="Monitored directory")
    parser.add_argument("-V", help="Verification file, not in monitored directory")
    parser.add_argument("-R", help="Report file, not in monitored directory")
    parser.add_argument("-H", help="Hash function", choices=["SHA-1", "MD-5"])
    return parser.parse_args()

def initializationMode(args):
    print("Initialization mode")
    if args.D: # Check if user provided argument
        if(os.path.isdir(args.D)): # Check if directory exist
            print("{} exists".format(args.D))
            if args.V and args.R: # Check if user provided verification and report argument
                if args.D not in args.V and args.R not in args.V: # Check if the paths is outside the directory
                    print("Verification and report ok")
                    # check if verification and report file exists
                    if os.path.exists(args.V) or os.path.exists(args.R):
                        # User must do a choice
                        ans = ""
                        while(ans != "yes" and ans != "no"):
                            ans = input("Should we overwrite verification {} and report {} yes/no : ".format(args.V, args.R))
                        if ans == "no":
                            print("The files will be preserved, goodbye")
                            quit() # terminate the program
                    # Continue if this was the users will
                    print("Will create new files")



                else:
                    print("'{}' Verification and '{}' report inside directory '{}', please specify outside {}".format(args.V, args.R, args.D, args.D))
            else: # args.V && R is provided
                print("Specify verification file and Report file")
        else: #isdir args.D
            print("{} is not existing".format(args.D))
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
        print("You need to specify if the mode is Initialization or Verification")


if __name__ == "__main__":
    main()
