#!/usr/bin/python
import os
import random
import shutil
import socket
import subprocess

def mkTmpDir():
    while True:
        dr = 'pin_wd/pin_wd_%d' % random.randint(0,1000000000000)
        try:
            os.mkdir(dr)
            return dr
        except:
            pass


def runTask(program, args, inputs):
    print "Starting task on program %s." % program[0]
    dr = mkTmpDir()
    odr = os.getcwd()
    shutil.copy(program[0], dr)
    os.chdir(dr)



    pinCmd = ['pin', '-t', '../../confuzzer.so'] + args + ['--'] + program
    print inputs, pinCmd
    for k,v in inputs.iteritems():
        f = open(k, 'w')
        f.write(v.decode('hex'))
        f.close()

    subprocess.call(pinCmd)

    idnt = "%s:%s" % (socket.gethostname(), dr)
    data = idnt + '\n========\n' + open('execution.dat').read()
    os.chdir(odr)
    return data


import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer

server = SimpleXMLRPCServer(("0.0.0.0", 7331))
print "Listening on port 7331..."
server.register_function(runTask, "runTask")
server.serve_forever()
