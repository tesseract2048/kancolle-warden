#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
 @author:   hty0807@gmail.com
"""
import time
import threading
import sys
import signal
from client_simulator import ClientSimulator
from common import *

VERSION = 'EUSTIA'
DATE = 'Feb 1st, 2014'

class LoopWorker(threading.Thread):
    def __init__(self, client, name, interval):
        threading.Thread.__init__(self)
        self.client = client
        self.name = name
        self.interval = interval

    def run(self):
        println('%s every %s secs' % (self.name, self.interval), YELLOW)
        while True:
            time.sleep(self.interval)
            self.client.lock()
            method = getattr(self.client, self.name)
            method()
            self.client.unlock()

def getworker(client, name, interval):
    th = LoopWorker(client, name, interval)
    th.start()
    return th

def signal_handler(signal, frame):
    sys.exit(0)

def main():
    if len(sys.argv) < 3:
        println('Usage: kancolle_warden.py <username> <password> [proxy]', RED)
        return
    proxy = None
    if len(sys.argv) > 3:
        proxy = sys.argv[3]
    signal.signal(signal.SIGINT, signal_handler)
    println('KanColle WARDEN', CYAN)
    println('Version: %s (%s)' % (VERSION, DATE), CYAN)
    println('Please wait while client simulator is initializing...', YELLOW)
    client = ClientSimulator(proxy)
    try:
        client.login(sys.argv[1], sys.argv[2])
        client.getincentive()
        client.start()
    except Exception, e:
        println('ERROR: %s' % str(e), RED)
        return
    println('entered mission loop.', RED)
    threads = []
    threads.append(getworker(client, 'logincheck', 29))
    threads.append(getworker(client, 'deckport', 17))
    for th in threads:
        th.join()

main()
