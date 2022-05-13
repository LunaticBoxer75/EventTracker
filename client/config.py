import datetime
import os
from termcolor import colored

def printError(error):
    print(colored(error, "red"))

def checkPath(path):
    if(os.path.exists(path)):
        return
    else:
        printError("Path " + path + " does not exist. Kindly correct the path in config.py file or create the desired path. Exiting...")
        exit(1)

DATABASE_NAME = "events"

SHA256_CMD = "sha256sum {fPath}"
AUDIT_MIN_TIMESTAMP = datetime.datetime(2004, 1, 1)
AUSEARCH_CMD = "ausearch -f {fPath} --start \'{startDate}\' \'{startTime}\'"
DATE_FORMATSTR = "%m/%d/%Y"
TIME_FORMATSTR = "%H:%M:%S"
AUSEARCH_DATETIME_FORMATSTR = "%a %b %d %H:%M:%S %Y"
AUDITCTL_ADDWATCH_CMD = "auditctl -w {path} -p wxa"
AUSEARCH_USERSTART_CMD = "ausearch -ts \'{lastLoggedDate}\' \'{lastLoggedTime}\' -m USER_START"
AUSEARCH_USEREND_CMD = "ausearch -ts \'{lastLoggedDate}\' \'{lastLoggedTime}\' -m USER_END"
AUSEARCH_FAILEDLOGIN_CMD = "ausearch -ts \'{lastLoggedDate}\' \'{lastLoggedTime}\' -m USER_LOGIN -sv no"

LSMOD_CMD = "lsmod"
RMMOD_CMD = "rmmod {mod}"
DUMP_FILEPATH = "/home/ciatc/image.mem"
LIME_INSMOD_CMD = "insmod {modPath} \"path="+DUMP_FILEPATH+" format=lime\""
MEMDUMP_MOD_NAME = "lime"

# place the lime kernel module file in the same directory as config.py
MEMDUMP_MOD_FILEPATH = os.path.abspath("./lime-5.4.0-105-generic.ko")
# change profile name according to the convention "Ubuntu_5.4.0-105-generic_profile.zip" profile is named as "LinuxUbuntu_5_4_0-105-generic_profilex64"
LINUX_PROFILE_NAME = "LinuxUbuntu_5_4_0-105-generic_profilex64"
DUMP_FILEPATH1 = "file://"+DUMP_FILEPATH
FORENSICS_PYTHON2 = "python2 forensics.py"
FORENSIC_DIR = '/tmp/forensics/'

BRUTEFORCE_THRES = 10
BRUTEFORCE_MSG = "Bruteforce attempts made by the following IP address: "

DDOS_THRES = 10
DDOS_MSG = "DDOS attack detected"

ILLEGAL_DIRS = ['/boot']
ILLEGAL_CHANGES_MSG = "Illegal file changes detected in the following directory: "

NEW_LOGIN_IP_MSG = "Successful login for username: {username} was performed by the IP: {ipAddress} for the first time"

MALICIOUS_CMNDS = ['/usr/bin/rm']
MALICIOUS_CMND_MSG = "The malicious command: {cmd} was ran by user: {username}"

AUTH_LOGS_FILEPATH = '/var/log/auth.log'

checkPath(os.path.split(DUMP_FILEPATH)[0])
checkPath(MEMDUMP_MOD_FILEPATH)
checkPath(AUTH_LOGS_FILEPATH)