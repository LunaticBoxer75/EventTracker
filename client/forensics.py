import copy, StringIO, json, config
import volatility.conf as conff
import volatility.registry as reg
import volatility.commands as coms
import volatility.addrspace as addr
import volatility.plugins.linux.dmesg as dmesg
import volatility.plugins.linux.bash as bash
import volatility.plugins.linux.pslist as pslist
import volatility.plugins.linux.lsmod as lsmod
import volatility.plugins.linux.ifconfig as ifconfig
import volatility.plugins.linux.mount as lmount
import volatility.plugins.linux.arp as arp
import volatility.plugins.linux.common as common
from dateutil import parser
import datetime
import json
import os
import time
import socket
import sys

def getConfig():
    reg.PluginImporter()
    configuration=conff.ConfObject()
    reg.register_global_options(configuration,coms.Command)
    reg.register_global_options(configuration,addr.BaseAddressSpace)
    configuration.parse_options()
    configuration.PROFILE = config.LINUX_PROFILE_NAME
    configuration.LOCATION = config.DUMP_FILEPATH1
    return configuration

def bashHistory(configuration):
    strio = StringIO.StringIO()
    plugin = bash.linux_bash(copy.deepcopy(configuration))
    plugin.render_json(strio, plugin.calculate())
    records = json.loads(strio.getvalue())
    loggedTime = time.mktime(datetime.datetime.now().timetuple())
    columns = records['columns']
    eventList = []
    for row in records['rows']:
        eventJson = {}
        for index, colName in enumerate(columns):
            if('time' in colName.lower()):
                row[index] = time.mktime(parser.parse(row[index]).timetuple())
            eventJson[colName] = row[index]
        eventJson['loggedTime'] = loggedTime
        eventList.append(eventJson)
    file = open(config.FORENSIC_DIR + 'bash_hist', 'wb')
    json.dump(eventList, file)
    file.close()

def dmesgOutput(configuration):
    plugin = dmesg.linux_dmesg(copy.deepcopy(configuration))
    kernelLogs = plugin.calculate().next().split('\n')
    logs = []
    loggedTime = time.mktime(datetime.datetime.now().timetuple())
    for log in kernelLogs:
        if(log.strip() == ''):
            continue
        logId = float(log[log.find('[')+1:log.find(']')])
        logData = log[log.find(']')+1:]
        logs.append({'logId': logId, 'message': logData, 'loggedTime': loggedTime})
    file = open(config.FORENSIC_DIR + 'kernel_logs', 'wb')
    json.dump(logs, file)
    file.close()

def processInfo(configuration):
    plugin = pslist.linux_pslist(copy.deepcopy(configuration))
    processes = plugin.calculate()
    procList = []
    for process in processes:
        procDict = {}
        procDict['pid'] = int(process.pid)
        procDict['uid'] = int(process.uid)
        procDict['gid'] = int(process.gid)
        procDict['name'] = process.comm
        procDict['cmdline'] = process.get_commandline()
        procDict['startTime'] = int(process.get_task_start_time())
        procDict['parentPid'] = int(process.parent.pid)
        procDict['envVars'] = process.get_environment()
        execs = []
        for elf in process.elfs():
            execs.append(elf[3])
        procDict['execs'] = execs
        procDict['cwd'] = process.getcwd()
        netSockets = []
        for sock in process.netstat():
            if(sock[0] == socket.AF_INET):
                netSockets.append((sock[1][1], str(sock[1][2]), int(sock[1][3]), str(sock[1][4]), int(sock[1][5]), sock[1][6]))
        procDict['netSockets'] = netSockets
        lsof = []
        for file, fd in process.lsof():
            lsof.append((fd, common.get_path(process, file)))
        procDict['lsof'] = lsof
        procList.append(procDict)
    file = open(config.FORENSIC_DIR + 'process_info', 'wb')
    json.dump(procList, file)
    file.close()

def kernelMods(configuration):
    plugin = lsmod.linux_lsmod(copy.deepcopy(configuration))
    result = plugin.calculate()
    modules = []
    for res in result:
        moduleName = str(res[0].name)
        parameters = res[-1]
        loggedTime = time.mktime(datetime.datetime.now().timetuple())
        module = {
            'name': moduleName,
            'parameters': parameters,
            'loggedTime': loggedTime
        }
        modules.append(module)
    file = open(config.FORENSIC_DIR + 'kernel_mods', 'wb')
    json.dump(modules, file)
    file.close()

def networkInterfaces(configuration):
    plugin = ifconfig.linux_ifconfig(copy.deepcopy(configuration))
    result = plugin.calculate()
    interfaces = []
    for res in result:
        interface = {}
        interface['interface'] = str(res[0])
        interface['ip'] = str(res[1])
        interface['mac'] = str(res[2])
        interface['loggedTime'] = time.mktime(datetime.datetime.now().timetuple())
        interfaces.append(interface)
    file = open(config.FORENSIC_DIR + 'network_interfaces', 'wb')
    json.dump(interfaces, file)
    file.close()

def mountInfo(configuration):
    plugin = lmount.linux_mount(copy.deepcopy(configuration))
    result = plugin.calculate()
    mounts = []
    for res in result:
        mount = {}
        mount['device'] = str(res[1])
        mount['path'] = str(res[2])
        mount['filesystem'] = str(res[3])
        mount['perms'] = str(res[4])+str(res[5])
        mount['loggedTime'] = time.mktime(datetime.datetime.now().timetuple())
        mounts.append(mount)
    file = open(config.FORENSIC_DIR + 'mount_info', 'wb')
    json.dump(mounts, file)
    file.close()

def arpCache(configuration):
    plugin = arp.linux_arp(copy.deepcopy(configuration))
    result = plugin.calculate()
    entries = []
    for res in result:
        entry = {}
        entry['ip'] = str(res.ip)
        entry['mac'] = str(res.mac)
        entry['interface'] = str(res.devname)
        entry['loggedTime'] = time.mktime(datetime.datetime.now().timetuple())
        entries.append(entry)
    file = open(config.FORENSIC_DIR + 'arp_cache', 'wb')
    json.dump(entries, file)
    file.close()

def generateForensics():
    if(not(os.path.isdir(config.FORENSIC_DIR))):
        os.mkdir(config.FORENSIC_DIR)
    volConfig = getConfig()
    checklist = list(map(int, sys.argv[1].split(',')))
    if(checklist[0]):
        dmesgOutput(volConfig)
    if(checklist[1]):
        bashHistory(volConfig)
    if(checklist[2]):
        processInfo(volConfig)
    if(checklist[3]):
        kernelMods(volConfig)
    if(checklist[4]):
        networkInterfaces(volConfig)
    if(checklist[5]):
        mountInfo(volConfig)
    if(checklist[6]):
        arpCache(volConfig)
    print("Success")

generateForensics()