import datetime
import config
import audit
import database
import events
from watchdog.observers.inotify import InotifyObserver
from watchdog.events import FileSystemEventHandler

class Handler(FileSystemEventHandler):
    def on_modified(self, event):
        if(not event.is_directory):
            parseLoginLogs()

def parseUserActivityString(keyValuePairs, logData, timeString):
    logData['time'] = datetime.datetime.strptime(timeString, config.AUSEARCH_DATETIME_FORMATSTR)
    logData['ipAddress'] = keyValuePairs['addr']
    logData['sessionId'] = keyValuePairs['ses']
    logData['username'] = audit.parseString(keyValuePairs['acct'])
    logData['terminal'] = keyValuePairs['terminal']
    logData['exe'] = audit.parseString(keyValuePairs['exe'])
    if(keyValuePairs['res'].find('success') == -1):
        logData['success'] = False
    else:
        logData['success'] = True

typeMap = {
    'USER_START' : parseUserActivityString,
    'USER_END' : parseUserActivityString,
    'USER_LOGIN' : parseUserActivityString
}

def parseUserActivityLogs(logs):
    logList = []
    for log in logs:
        logData = {}
        log = log.strip()
        if(not log):
            continue
        lines = log.split('\n')
        timeString = lines[0][6:]
        lines[1] = lines[1].strip()
        if(not lines[1]):
            continue
        keyValuePairs = audit.parseKeyValueString(lines[1])
        if(typeMap.get(keyValuePairs['type'])):
            typeMap[keyValuePairs['type']](keyValuePairs, logData, timeString)
        logList.append(logData)
    return logList

userSessionTrack = {}
sessionIPAddress = {}

def parseSuccessfulLoginLogs(lastLoggedDate, lastLoggedTime):
    userStartCmd = config.AUSEARCH_USERSTART_CMD.format(lastLoggedDate = lastLoggedDate, lastLoggedTime = lastLoggedTime)
    userStartLogs = audit.runShellCMD(userStartCmd)

    userEndCmd = config.AUSEARCH_USEREND_CMD.format(lastLoggedDate = lastLoggedDate, lastLoggedTime = lastLoggedTime)
    userEndLogs = audit.runShellCMD(userEndCmd)

    if("no matches" in userStartLogs):
        return

    userStartLogs = parseUserActivityLogs(userStartLogs.split('----'))
    userEndLogs = parseUserActivityLogs(userEndLogs.split('----'))
    index1 = 0
    index2 = 0

    while(index1 < len(userStartLogs) or index2 < len(userEndLogs)):
        if(index2 == len(userEndLogs) or (index1 < len(userStartLogs) and userStartLogs[index1]['time'] <= userEndLogs[index2]['time'])):
            sesId = userStartLogs[index1]['sessionId']
            user = userStartLogs[index1]['username']
            term = userStartLogs[index1]['terminal']
            exe = userStartLogs[index1]['exe']
            ipAddress = userStartLogs[index1]['ipAddress']
            if(ipAddress == '?'):
                if(sessionIPAddress.get(sesId)):
                    userStartLogs[index1]['ipAddress'] = sessionIPAddress.get(sesId)
            else:
                sessionIPAddress[sesId] = ipAddress
            if(userSessionTrack.get((sesId, user, term, exe))):
                userLog = userStartLogs[index1]
                userLog['loginTime'] = userLog['time']
                del userLog['time']
                dbEntry = database.addLoginActivity(**userLog)
                userSessionTrack[(sesId, user, term, exe)].append(dbEntry)
            else:
                userLog = userStartLogs[index1]
                userLog['loginTime'] = userLog['time']
                del userLog['time']
                events.detectBruteforce(userLog['ipAddress'], userLog['loginTime'], True)
                events.detectLoginFromNewIP(userLog['ipAddress'], userLog['username'], userLog['loginTime'])
                dbEntry = database.addLoginActivity(**userLog)
                userSessionTrack[(sesId, user, term, exe)] = [dbEntry, ]
            index1 += 1
        else:
            try:
                sesId = userEndLogs[index2]['sessionId']
                user = userEndLogs[index2]['username']
                term = userEndLogs[index2]['terminal']
                exe = userEndLogs[index2]['exe']
                dbEntry = userSessionTrack[(sesId, user, term, exe)][-1]
                ipAddress = dbEntry.ipAddress
                userSessionTrack[(sesId, user, term, exe)].pop()
                if(ipAddress != '?' and sessionIPAddress.get(sesId)):
                    del sessionIPAddress[sesId]
                dbEntry.logoutTime = userEndLogs[index2]['time']
                dbEntry.save()
            except:
                pass
            index2 += 1

def parseFailedLoginLogs(lastLoggedDate, lastLoggedTime):
    failedLoginCmd = config.AUSEARCH_FAILEDLOGIN_CMD.format(lastLoggedDate = lastLoggedDate, lastLoggedTime = lastLoggedTime)
    failedLoginLogs = audit.runShellCMD(failedLoginCmd)
    failedLoginLogs = parseUserActivityLogs(failedLoginLogs.split('----'))

    for logData in failedLoginLogs:
        logData['loginTime'] = logData['time']
        logData['logoutTime'] = logData['time']
        del logData['time']
        events.detectBruteforce(logData['ipAddress'], logData['loginTime'], False)
        events.detectDDOS(logData['loginTime'])
        database.addLoginActivity(**logData)


def parseLoginLogs():
    lastLoggedTimestamp = database.getLastLoginLogTimestamp()
    lastLoggedDate = lastLoggedTimestamp.strftime(config.DATE_FORMATSTR)
    lastLoggedTime = lastLoggedTimestamp.strftime(config.TIME_FORMATSTR)

    parseSuccessfulLoginLogs(lastLoggedDate, lastLoggedTime)
    parseFailedLoginLogs(lastLoggedDate, lastLoggedTime)

def initLoginMonitor():
    parseLoginLogs()
    handler = Handler()
    observer = InotifyObserver()
    filePath = config.AUTH_LOGS_FILEPATH
    observer.schedule(handler, filePath, recursive=True)
    observer.start()
    try:
        while observer.is_alive():
            observer.join(1)
    finally:
        observer.stop()
        observer.join()
