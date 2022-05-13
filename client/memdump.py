import audit
import config
import database
import os
import json
from datetime import datetime

fileToDatabase = {
    'bash_hist': database.addBashHistory,
    'kernel_logs': database.addKernelLog,
    'process_info': database.addProcessInfo,
    'arp_cache': database.addARPCache,
    'kernel_mods': database.addKernelMods,
    'mount_info': database.addMountInfo,
    'network_interfaces': database.addNetworkInterface
}

def createMemDump():
    existingMods = audit.runShellCMD(config.LSMOD_CMD)
    if("lime" in existingMods):
        audit.runShellCMD(config.RMMOD_CMD.format(mod=config.MEMDUMP_MOD_NAME))
    audit.runShellCMD(config.LIME_INSMOD_CMD.format(modPath=config.MEMDUMP_MOD_FILEPATH))

def generate_forensics(evidenceChecklist):
    output = audit.runShellCMD(config.FORENSICS_PYTHON2 + " " + ','.join(map(str, evidenceChecklist)))
    if(not('Success' in output)):
        config.printError("Error generating forensics from memory dump. Kindly check the profile used and the memory dump file.")
        return
    files = os.listdir(config.FORENSIC_DIR)
    for file in files:
        dbFunction = fileToDatabase[file]   
        fp = open(config.FORENSIC_DIR+file)
        entries = json.load(fp)
        for entry in entries:
            for key in entry:
                if('time' in key.lower()):
                    entry[key] = datetime.fromtimestamp(entry[key])
            dbFunction(**entry)

def memoryForensics(evidenceChecklist):
    createMemDump()
    generate_forensics(evidenceChecklist)