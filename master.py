#!/usr/bin/python
import xmlrpclib
from Queue import Queue, PriorityQueue
from threading import Thread

WORKERS = [('localhost', 7331)]

tasks = PriorityQueue()
results = Queue()

def worker(host, port=7331):
    #print "http://%s:%d/" % (host, port)
    w = xmlrpclib.ServerProxy("http://%s:%d/" % (host, port))
    while True:
        task = tasks.get(True)[1]
        response = w.runTask(task['program'], task['args'], task['inputs'])
        results.put((task['path'], response))
        tasks.task_done()

def assignTask(data, priority=100):
    tasks.put((priority, data))

def getResult():
    (path, data) = results.get(True)
    data = data.split('========', 1)[1].strip().split('\n')
    results.task_done()
    return (path, data)

def startWorkers():
    for (h,p) in WORKERS:
        t = Thread(target=worker, args=(h,p))
        t.daemon = True
        t.start()

startWorkers()
