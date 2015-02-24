#!/usr/bin/python
import subprocess

class FuzzedProgram:
    program = None
    tainted = []
    
    def __init__(self, program, taintedInputs):
        self.program = program.split(' ')
        self.tainted = taintedInputs

    def getTainted(self):
        return '|'.join([':'.join(t) for t in self.tainted])

    def step(self):
        pinCmd = ['pin', '-t', 'confuzzer.so', '-tainted-input', self.getTainted(), '--']
        subprocess.call(pinCmd + self.program)

def run(program, taintedInput):
    print "Testing %s with tainted input %s" % (program, taintedInput)
    fp = FuzzedProgram(program, taintedInput)
    fp.step()
