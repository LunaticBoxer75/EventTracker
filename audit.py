import events
import os
import database
import datetime
import config
import pwd

def runShellCMD(cmd):
	proc = os.popen(cmd)
	output = proc.read()
	proc.close()
	return output 

def getSHAHash(filePath):
	output = runShellCMD(config.SHA256_CMD.format(fPath = filePath))
	try:
		shahash = output.split()[0]
		return shahash
	except:
		return ""

def addAuditRule(path):
	runShellCMD(config.AUDITCTL_ADDWATCH_CMD.format(path=path))

def parseKeyValueString(string):
	hashMap = {}
	keyValuePairs = string.split()
	for pair in keyValuePairs:
		pair = pair.strip()
		key, value = pair.split('=', 1)
		hashMap[key] = value
	return hashMap

def parseString(string):
	if(string[0] == "\""):
		return string[1:-1]
	else:
		return bytearray.fromhex(string).decode()

def parseCWDType(keyValuePairs, logData):
	logData['cwd'] = parseString(keyValuePairs['cwd'])

def parsePATHType(keyValuePairs, logData):
	path = parseString(keyValuePairs['name'])
	ignoreNametypes = ['PARENT', 'UNKNOWN']
	if(keyValuePairs['nametype'] in ignoreNametypes):
		return
	fileDir, fileName = os.path.split(path)
	if(keyValuePairs.get('nametype') == 'DELETE' and logData.get('operation') == 'CREATE'):
		if(len(logData['fileDir']) > 0):
			logData["tempFile"] = logData['fileDir'] + "/" +logData['fileName']
		else:
			logData["tempFile"] = logData['fileName']
		logData['fileDir'] = fileDir
		logData['fileName'] = fileName
		logData['inode'] = int(keyValuePairs['inode'])
		logData['mode'] = keyValuePairs['mode']
		logData['operation'] = "RENAMED to "
		return
	logData['fileDir'] = fileDir
	logData['fileName'] = fileName
	logData['inode'] = int(keyValuePairs['inode'])
	logData['mode'] = keyValuePairs['mode']
	if(keyValuePairs['nametype'] == 'NORMAL'):
		keyValuePairs['nametype'] = "MODIFIED"
	logData['operation'] = keyValuePairs['nametype']

def parseSYSCALLType(keyValuePairs, logData):
	logData['username'] = pwd.getpwuid(int(keyValuePairs['euid'])).pw_name
	logData['executable'] = parseString(keyValuePairs['exe'])
	logData['sessionId'] = int(keyValuePairs['ses'])

def parsePROCTITLEType(keyValuePairs, logData):
	logData['proctitle'] = parseString(keyValuePairs['proctitle'])
	logData['auditId'] = keyValuePairs['msg'].split(':')[1][:-1]

def correctPath(logData, field):
	if(len(logData[field])==0 or logData[field][0]!='/'):
		logData[field] = os.path.realpath(logData['cwd']+'/'+logData[field])

typeMap = {
	'CWD' : parseCWDType,
	'PATH' : parsePATHType,
	'SYSCALL' : parseSYSCALLType,
	'PROCTITLE' : parsePROCTITLEType
}

def getFileSize(filePath, logData):
	try:
		logData['size'] = os.stat(filePath).st_size
	except:
		logData['size'] = 0

def parseAuditLogs(filePath):
	fileDir, fileName = os.path.split(filePath)
	print(fileDir, fileName)
	lastTimeStamp = database.getLatestTimestamp(fileName, fileDir)
	startDate = lastTimeStamp.strftime(config.DATE_FORMATSTR)
	startTime = lastTimeStamp.strftime(config.TIME_FORMATSTR)
	ausearchCommand = config.AUSEARCH_CMD.format(fPath=fileName, startDate=startDate, startTime=startTime)
	auditLogString = runShellCMD(ausearchCommand)
	if("no matches" in auditLogString):
		return
	auditLogs = auditLogString.split('----')
	for log in auditLogs:
		logData = {}
		logData['fileHash'] = getSHAHash(filePath)
		log = log.strip()
		if(not log):
			continue
		lines = log.split('\n')
		tempString = lines[1].split(' ', 2)[1]
		timeString = float(tempString[10:tempString.find(':')])
		logData['timeStamp'] = datetime.datetime.fromtimestamp(timeString)
		getFileSize(filePath, logData)
		for line in lines[1:]:
			line = line.strip()
			if(not line):
				continue
			keyValuePairs = parseKeyValueString(line)
			if(typeMap.get(keyValuePairs['type'])):
				typeMap[keyValuePairs['type']](keyValuePairs, logData)
		correctPath(logData, 'fileDir')
		if(logData.get('tempFile')):
			correctPath(logData, 'tempFile')
			logData['operation'] += ' ' + logData['tempFile']
			del logData['tempFile']
		if(logData['fileDir'] != fileDir):
			continue
		events.detectIllegalFileChanges(logData['fileDir'], logData['timeStamp'])
		events.detectMaliciousCommands(logData['executable'], logData['username'], logData['timeStamp'])
		print(logData)
		database.addLogInstance(**logData)


