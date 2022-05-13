import config
import os
import socket
import hashlib
from datetime import timedelta
from mongoengine import connect, Document, StringField, FloatField, DateTimeField, IntField, BooleanField, ListField, DictField

connector = connect(config.DATABASE_NAME)

clientID = os.getlogin()+"@"+socket.gethostname()

class FileLog(Document):
    auditId = StringField(required = True)
    fileName = StringField(required = True)
    fileDir = StringField(required = True)
    timeStamp = DateTimeField(required = True)
    fileHash = StringField(required = True)
    username = StringField(required = True)
    proctitle = StringField(required = True)
    executable = StringField()
    cwd = StringField()
    size = IntField(required = True)
    inode = IntField(required = True)
    mode = IntField(required = True)
    sessionId = IntField(required = True)
    operation = StringField(required = True)
    clientID = StringField(required = True)

class LoginActivity(Document):
    ipAddress = StringField(required = True)
    sessionId = IntField(required = True)
    username = StringField(required = True)
    loginTime = DateTimeField(required = True)
    logoutTime = DateTimeField()
    success = BooleanField(required = True)
    terminal = StringField(required = True)
    exe = StringField(required = True)
    clientID = StringField(required = True)

class BashHistory(Document):
    loggedTime = DateTimeField()
    CommandTime = DateTimeField()
    Command = StringField()
    Pid = IntField()
    Name = StringField()
    clientID = StringField(required = True)

class KernelLogs(Document):
    logId = FloatField()
    message = StringField()
    loggedTime = DateTimeField()
    clientID = StringField(required = True)

class ProcessInfo(Document):
    startTime = DateTimeField()
    pid = IntField()
    uid = IntField()
    gid = IntField()
    name = StringField()
    cmdline = StringField()
    cwd = StringField()
    parentPid = IntField()
    envVars = StringField()
    netSockets = ListField()
    execs = ListField()
    lsof = ListField()
    clientID = StringField(required = True)

class KernelMods(Document):
    name = StringField()
    parameters = StringField()
    loggedTime = DateTimeField()
    clientID = StringField(required = True)

class NetworkInterface(Document):
    interface = StringField()
    ip = StringField()
    mac = StringField()
    loggedTime = DateTimeField()
    clientID = StringField(required = True)

class MountInfo(Document):
    device = StringField()
    path = StringField()
    filesystem = StringField()
    perms = StringField()
    loggedTime = DateTimeField()
    clientID = StringField(required = True)

class ARPCache(Document):
    ip = StringField()
    mac = StringField()
    interface = StringField()
    loggedTime = DateTimeField()
    clientID = StringField(required = True)

class Events(Document):
    eventTime = DateTimeField()
    eventData = StringField()
    clientID = StringField(required = True)

def addLogInstance(auditId, fileName, fileDir, timeStamp, fileHash, username, proctitle,  size, inode, mode, sessionId, operation, executable=None, cwd=None):
    object = FileLog.objects(clientID = clientID, operation = operation, auditId = auditId, fileName = fileName, fileDir = fileDir, timeStamp = timeStamp, fileHash = fileHash, username = username, proctitle = proctitle, executable = executable, cwd = cwd, size = size, inode = inode, mode = mode, sessionId = sessionId)
    if(object):
        return
    FileLog(clientID = clientID, operation = operation, auditId = auditId, fileName = fileName, fileDir = fileDir, timeStamp = timeStamp, fileHash = fileHash, username = username, proctitle = proctitle, executable = executable, cwd = cwd, size = size, inode = inode, mode = mode, sessionId = sessionId).save()

def getLatestTimestamp(fileName, fileDir):
    fileLog = FileLog.objects(fileName = fileName, fileDir = fileDir)
    if(fileLog.count() > 0):
        lastTimestamp = max(fileLog.values_list('timeStamp'))
        return lastTimestamp + timedelta(milliseconds=10)
    else:
        return config.AUDIT_MIN_TIMESTAMP

def addLoginActivity(**kwargs):
    kwargs['clientID'] = clientID
    object = LoginActivity.objects(**kwargs)
    if(object):
        return
    return LoginActivity(**kwargs).save()

def getLastLoginLogTimestamp():
    loginActivity = LoginActivity.objects()
    if(loginActivity.count() > 0):
        lastLogoutTimestamp = max(loginActivity.filter(logoutTime__ne=None).values_list('logoutTime'))
        lastLoginTimestamp = max(loginActivity.values_list('loginTime'))
        lastTimestamp = max(lastLoginTimestamp, lastLogoutTimestamp)
        return lastTimestamp
    return config.AUDIT_MIN_TIMESTAMP

def addBashHistory(**kwargs):
    kwargs['clientID'] = clientID
    object = BashHistory.objects(CommandTime = kwargs['CommandTime'], Command = kwargs['Command'], Pid = kwargs['Pid'], Name = kwargs['Name'], clientID = kwargs['clientID'])
    if(object):
        return
    BashHistory(**kwargs).save()

def addKernelLog(**kwargs):
    kwargs['clientID'] = clientID
    KernelLogs(**kwargs).save()

def addProcessInfo(**kwargs):
    kwargs['clientID'] = clientID
    ProcessInfo(**kwargs).save()

def addKernelMods(**kwargs):
    kwargs['clientID'] = clientID
    KernelMods(**kwargs).save()

def addNetworkInterface(**kwargs):
    kwargs['clientID'] = clientID
    NetworkInterface(**kwargs).save()

def addMountInfo(**kwargs):
    kwargs['clientID'] = clientID
    MountInfo(**kwargs).save()

def addARPCache(**kwargs):
    kwargs['clientID'] = clientID
    ARPCache(**kwargs).save()

def addEvent(eventTime, eventData):
    object = Events(clientID = clientID, eventTime = eventTime, eventData = eventData)
    if(object):
        return
    Events(clientID = clientID, eventTime = eventTime, eventData = eventData).save()