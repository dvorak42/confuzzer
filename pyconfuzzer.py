#!/usr/bin/python
import subprocess
import z3

import parser
import master

# TODO: Hook into Server

class FuzzedProgram:
    program = None
    tainted = []
    paths = {}
    value = ''
    
    def __init__(self, program, taintedInputs):
        self.program = program.split(' ')
        self.tainted = taintedInputs

    def getTainted(self):
        return '|'.join([':'.join(t) for t in self.tainted])

    def setInput(self, val):
        self.value = val

    def step(self):
        master.assignTask({'program': self.program, 'args': ['-tainted-input', self.getTainted()], 'inputs': {self.tainted[0][1]: self.value.encode('hex')}})
        #f = open(self.tainted[0][1], 'w')
        #f.write(self.value)
        #f.close()

        #pinCmd = ['pin', '-t', 'confuzzer.so', '-tainted-input', self.getTainted(), '--']
        #subprocess.call(pinCmd + self.program)
        #self.data = open('execution.dat').read().split('\n')

    def process(self):
        data = master.getResult().split('\n')
        branchStrings = []
        constraintStrings = []
        solver = z3.Solver()
        vrs = {}
        for i in range(32):
            vrs['$E%d' % i] = z3.BitVec('$E%d' % i, 32)
        for l in data:
            if l.startswith('br_'):
                bid = l.split(":")[0]
                instr = l.split(":")[1][1:].split("(")[0].strip()
                var = l.split(":")[1][1:].split(" - ")[1]
                branchStrings.append((bid, parser.asmInstruction(instr, var)))
            elif l.startswith('  '):
                var = l.split(":")[0].strip()
                if not var in vrs:
                    vrs[var] = z3.BitVec(var, 32)
                instr = l.split(":")[1][1:].split("(")[0].strip()
                eqtn = l.split(" - ")[-1].strip()
                constraintStrings.append((var, parser.asmInstruction(instr, eqtn)))
        for (v,c) in constraintStrings:
            parser.asmZ3(solver, vrs, c)
        for (b,c) in branchStrings:
            parser.asmZ3(solver, vrs, c)
        print solver.check()
        valM = {}
        m = solver.model()
        for v in m:
            if str(v).startswith('$E'):
                valM[str(v)[2:]] = m[v]
        self.value = ''
        for i in range(16):
            if str(i) in valM:
                self.value += chr(valM[str(i)].as_long())
            else:
                break
        self.paths[self.value] = branchStrings
        # for b in branchStrings:
        #     print b
        # for c in constraintStrings:
        #     print c[1]


def run(program, taintedInput):
    print "Testing %s with tainted input %s" % (program, taintedInput)
    fp = FuzzedProgram(program, taintedInput)
    fp.setInput('')
    while True:
        oi = fp.value
        fp.step()
        fp.process()
        if fp.value == oi:
            break
        print fp.value
