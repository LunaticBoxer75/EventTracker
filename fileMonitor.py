#!/usr/bin/python

from watchdog.observers.inotify import InotifyObserver
from watchdog.events import FileSystemEventHandler
import audit
from multiprocessing import Process
from loginMonitor import initLoginMonitor

class Handler(FileSystemEventHandler):
    def on_modified(self, event):
        if(not event.is_directory):
            p = Process(audit.parseAuditLogs(event.src_path))
            p.start()

    def on_moved(self, event):
        if(not event.is_directory):
            p = Process(audit.parseAuditLogs(event.src_path))
            p.start()
    
    def on_deleted(self, event):
        if(not event.is_directory):
            p = Process(audit.parseAuditLogs(event.src_path))
            p.start()
    
    def on_created(self, event):
        if(not event.is_directory):
            p = Process(audit.parseAuditLogs(event.src_path))
            p.start()

if __name__ == '__main__':
    p = Process(target = initLoginMonitor)
    p.start()

    handler = Handler()
    observer = InotifyObserver()
    filesToMonitor = open('files.txt')
    fileList = filesToMonitor.read().split('\n')
    for filePath in fileList:
        filePath = filePath.strip()
        if(not filePath):
            continue 
        audit.addAuditRule(filePath)
        observer.schedule(handler, filePath, recursive=True)
    observer.start()
    try:
        while observer.is_alive():
            observer.join(1)
    finally:
        observer.stop()
        observer.join()

