#!/usr/bin/python
import subprocess
import z3
from threading import Thread

import parser
import master
import viewer
# TODO: Hook into Server

class FuzzedProgram:
    program = None
    tainted = []
    paths = {}
    value = ''
    completed = {}
    queued = []
    problems = []
    prioritized = []
    
    def __init__(self, program, taintedInputs, draw=True):
        self.program = program.split(' ')
        self.tainted = taintedInputs
        self.iters = 0
        self.draw = draw
        if self.draw:
            viewer.startGraph()

    def getTainted(self):
        return '|'.join([':'.join(t) for t in self.tainted])

    def setInput(self, val):
        self.value = val
        

    def send(self, pathID, value, priority=100):
        master.assignTask({'path': pathID,
                           'program': self.program, 
                           'args': ['-tainted-input', self.getTainted()], 
                           'inputs': {self.tainted[0][1]: value.encode('hex')}}, priority)
        self.queued.append(pathID)
        #f = open(self.tainted[0][1], 'w')
        #f.write(self.value)
        #f.close()

        #pinCmd = ['pin', '-t', 'confuzzer.so', '-tainted-input', self.getTainted(), '--']
        #subprocess.call(pinCmd + self.program)
        #self.data = open('execution.dat').read().split('\n')

    def parse(self, data):
        branches = []
        constraints = []
        vrs = {}

        for l in data:
            if not l.startswith('br_') and not l.startswith('  '):
                continue
            idnt, eqtn = l.split(':', 1)
            idnt = idnt.strip()
            if idnt.startswith('br_'):
                asm = eqtn.split(' (', 1)[0].strip()
                state = eqtn.split('(', 1)[1].split(')', 1)[0].strip()
                var = eqtn.rsplit(' - ', 1)[1].strip()
                formula = parser.asmInstruction(asm, var)
                taken = parser.asmBranch(asm, state)
                branches.append((idnt, formula, taken))
            else:
                asm, eqtn = eqtn.split(' ::: ', 1)
                if not idnt in vrs:
                    vrs[idnt] = z3.BitVec(idnt, 32)
                ai = parser.asmInstruction(asm.strip(), eqtn.strip())
                if ai:
                    constraints.append((idnt, ai))
        return (branches, constraints, vrs)

    def process(self):
        self.send('', '')

        while len(self.queued):
            self.iters += 1
            print 'Left:', len(self.queued)
            (pathID, data) = master.getResult()
            self.queued.remove(pathID)
            if pathID in self.completed:
                continue
            if data[-1].strip() == 'SEGFAULT':
                (bS, cS, vrs) = self.parse(data[:-1])
                self.paths[pathID] = bS + [['SEGFAULT', pathID, '']]
                self.problems.append(pathID)
                continue
            (bS, cS, vrs) = self.parse(data)
            self.paths[pathID] = bS
            if self.draw:
                viewer.drawGraph(self.paths)
            for bi in range(len(bS)):
                solver = z3.Solver()
                for (v,cf) in cS:
                    parser.asmZ3(solver, vrs, cf)
                keep = bS[0:bi]
                negate = bS[bi]
                for (b, bf, bt) in keep:
                    parser.asmZ3(solver, vrs, bf, bt)
                parser.asmZ3(solver, vrs, negate[1], not negate[2])
                for k,v in vrs.iteritems():
                    if k.startswith('$E'):
                        solver.add(v >= 0)
                        solver.add(v < 256)
                if solver.check().r == 1:
                    valM = {}
                    m = solver.model()
                    maxRead = 0
                    for v in m:
                        if str(v).startswith('$E'):
                            valM[str(v)[2:]] = m[v]
                            maxRead = max(int(str(v)[2:]), maxRead)
                    value = ''
                    for i in range(maxRead+1):
                        if str(i) in valM:
                            value += chr(valM[str(i)].as_long())
                        else:
                            break
                    priority = 0
                    for i in range(len(keep)):
                        (b, _, bt) = keep[i]
                        if (i, b, bt) in self.prioritized:
                            priority += 1
                    (b, _, bt) = negate
                    if (len(keep), b, not bt) in self.prioritized:
                        priority += 1                        
                    if value not in self.queued and value not in self.completed and value != pathID:
                        print self.iters, value
                        self.send(value, value, 100-priority) 
            self.completed[pathID] = data
            

def userInput(fp):
    while True:
        i = raw_input('Prioritize Branch ((TRUE|FALSE)_ID): ')
        (val, i, name) = i.split('_',2)
        fp.prioritized.append((int(i), name, val.lower() == 'true'))

def run(program, taintedInput):
    print "Testing %s with tainted input %s" % (program, taintedInput)
    fp = FuzzedProgram(program, taintedInput, True)
    t = Thread(target=userInput, args=(fp,))
    #t.start()
    fp.setInput('')
    fp.process()
    #print fp.paths.keys()
    if fp.problems:
        print "Crashing Inputs:"
    for i in fp.problems:
        print "\t%s" % i
    viewer.drawGraph(fp.paths, True)
