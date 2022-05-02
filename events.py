import config
import datetime
import memdump
from database import LoginActivity, Events, addEvent

evidenceChecklist = {
    "detectBruteforce": [1, 1, 1, 1, 1, 1, 1],
    "detectDDOS": [1, 1, 1, 1, 1, 1, 1],
    "detectIllegalFileChanges": [1, 1, 1, 1, 0, 0, 0],
    "detectLoginFromNewIP": [1, 1, 1, 1, 1, 1, 1],
    "detectMaliciousCommands": [1, 1, 1, 1, 0, 0, 0]
}

def processEvent(time, eventData, eventName):
    events = Events.objects()
    if(events.count() > 0):
        lastTimestamp = max(events.values_list('eventTime'))
        if(lastTimestamp + datetime.timedelta(minutes = 10) < time):
            memdump.memoryForensics(evidenceChecklist=evidenceChecklist[eventName])
    else:
        memdump.memoryForensics(evidenceChecklist=evidenceChecklist[eventName])
    addEvent(time, eventData)

def detectBruteforce(ipAddress, time, success):
    if(success == True and LoginActivity.objects(ipAddress = ipAddress, loginTime__gt = time - datetime.timedelta(hours = 1), success = False).count() >= config.BRUTEFORCE_THRES):
        events = Events.objects()
        if(events.count() > 0):
            lastTimestamp = max(events.values_list('eventTime'))
            if(lastTimestamp + datetime.timedelta(minutes = 10) < time):
                memdump.memoryForensics(evidenceChecklist=evidenceChecklist[detectBruteforce.__name__])
        else:
            memdump.memoryForensics(evidenceChecklist=evidenceChecklist[detectBruteforce.__name__])
    elif(success == False and LoginActivity.objects(ipAddress = ipAddress, loginTime__gt = time - datetime.timedelta(hours = 1), success = False).count() >= config.BRUTEFORCE_THRES and Events.objects(eventTime__gt = time- datetime.timedelta(hours = 1), eventData__contains = config.BRUTEFORCE_MSG + ipAddress).count() == 0):
        eventData = config.BRUTEFORCE_MSG + ipAddress
        addEvent(time, eventData)

def detectDDOS(time):
    if(LoginActivity.objects(loginTime__gt = time - datetime.timedelta(hours = 1)).count() >= config.DDOS_THRES and Events.objects(eventTime__gt = time- datetime.timedelta(hours = 1), eventData = config.DDOS_MSG).count() == 0):
        eventData = config.DDOS_MSG
        processEvent(time = time, eventData = eventData, eventName = detectDDOS.__name__)

def detectIllegalFileChanges(fileDir, time):
    if(Events.objects(eventTime__gt = time- datetime.timedelta(minutes = 2), eventData = config.ILLEGAL_CHANGES_MSG).count() == 0 and fileDir in config.ILLEGAL_DIRS):
        eventData = config.ILLEGAL_CHANGES_MSG + fileDir
        processEvent(time = time, eventData = eventData, eventName=detectIllegalFileChanges.__name__)

def detectLoginFromNewIP(ipAddress, username, time):
    if(LoginActivity.objects(ipAddress = ipAddress, username = username).count() == 0):
        eventData = config.NEW_LOGIN_IP_MSG.format(username = username, ipAddress = ipAddress)
        processEvent(time = time, eventData = eventData, eventName = detectLoginFromNewIP.__name__)

def detectMaliciousCommands(executable, username, time):
    if(executable in config.MALICIOUS_CMNDS):
        print("Malicious command executed")
        eventData = config.MALICIOUS_CMND_MSG.format(cmd = executable, username = username)
        processEvent(time = time, eventData = eventData, eventName = detectMaliciousCommands.__name__)