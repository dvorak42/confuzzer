#!/usr/bin/python
import subprocess
import z3

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
    
    def __init__(self, program, taintedInputs):
        self.program = program.split(' ')
        self.tainted = taintedInputs
        self.iters = 0

    def getTainted(self):
        return '|'.join([':'.join(t) for t in self.tainted])

    def setInput(self, val):
        self.value = val
        

    def send(self, pathID, value):
        master.assignTask({'path': pathID,
                           'program': self.program, 
                           'args': ['-tainted-input', self.getTainted()], 
                           'inputs': {self.tainted[0][1]: value.encode('hex')}})
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
        
        for i in range(32):
            vrs['$E%d' % i] = z3.BitVec('$E%d' % i, 32)

        for l in data:
            if l.startswith('br_'):
                bid = l.split(":")[0]
                instr = l.split(":")[1][1:].split("(")[0].strip()
                state = l.split(":")[1][1:].split("(")[1].split(")")[0].strip()
                var = l.split(":")[1][1:].split(" - ")[1]
                formula = parser.asmInstruction(instr, var)
                taken = parser.asmBranch(instr, state)
                branches.append((bid, formula, taken))
            elif l.startswith('  '):
                var = l.split(":")[0].strip()
                if not var in vrs:
                    vrs[var] = z3.BitVec(var, 32)
                instr = l.split(":")[1][1:].split("(")[0].strip()
                eqtn = l.split(" - ")[-1].strip()
                constraints.append((var, parser.asmInstruction(instr, eqtn)))
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

            (bS, cS, vrs) = self.parse(data)
            self.paths[pathID] = bS
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
                for i2 in range(32):
                    solver.add(vrs['$E%d' % i2] >= 0)
                    solver.add(vrs['$E%d' % i2] < 256)
                if solver.check().r == 1:
                    valM = {}
                    m = solver.model()
                    for v in m:
                        if str(v).startswith('$E'):
                            valM[str(v)[2:]] = m[v]
                    value = ''
                    for i in range(16):
                        if str(i) in valM:
                            value += chr(valM[str(i)].as_long())
                        else:
                            break
                    if value not in self.queued and value not in self.completed and value != pathID:
                        print self.iters, value
                        self.send(value, value) 
            self.completed[pathID] = data
            



        branchStrings = []
        constraintStrings = []
        solver = z3.Solver()
        vrs = {}
        # for b in branchStrings:
        #     print b
        # for c in constraintStrings:
        #     print c[1]


def run(program, taintedInput):
    print "Testing %s with tainted input %s" % (program, taintedInput)
    viewer.startGraph()
    fp = FuzzedProgram(program, taintedInput)
    fp.setInput('')
    fp.process()
    print fp.paths.keys()
    viewer.drawGraph(fp.paths, True)
