#!/usr/bin/python
import subprocess
import z3

def asmInstruction(instr, eqtn):
    opc = instr.split(" ")[0]
    if instr.startswith('External Taint'):
        src = eqtn.split(' -> ')[0]
        dst = eqtn.split(' -> ')[1]
        return '%s = %s' % (dst, '$E%s' % src.replace('EXT_', ''))
    if opc == 'jnz':
        return '%s != 0' % eqtn
    elif opc == 'jz':
        return '%s == 0' % eqtn
    elif opc.startswith('mov') or opc == 'push' or opc == 'pop':
        src = eqtn.split(' -> ')[0]
        dst = eqtn.split(' -> ')[1]
        return '%s = %s' % (dst, src)
    elif opc == 'cmp':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1]        
        return '%s = %s - %s' % (dst, src2, src1)
    elif opc == 'test':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1]        
        return '%s = %s & %s' % (dst, src1, src2)
    elif opc == 'sub':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1]        
        return '%s = %s - %s' % (dst, src1, src2)
    elif opc == 'xor':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1]        
        return '%s = %s ^ %s' % (dst, src1, src2)
        
    print "Unknown instruction: %s (%s)" % (instr, eqtn)
    return ""

def asmZ3(solver, vrs, cnst, invert=False):
    def getZ3(v):
        if v in vrs:
            return vrs[v]
        else:
            try:
                return int(v, 16)
            except:
                print 'Unknown: %s' % v

    if ' == ' in cnst:
        left = cnst.split(" == ")[0]
        right = cnst.split(" == ")[1]
        if invert:
            return solver.add(getZ3(left) != getZ3(right))
        return solver.add(getZ3(left) == getZ3(right))
    elif ' != ' in cnst:
        left = cnst.split(" != ")[0]
        right = cnst.split(" != ")[1]
        if invert:
            return solver.add(getZ3(left) == getZ3(right))
        return solver.add(getZ3(left) != getZ3(right))

    left = cnst.split(" = ")[0]
    right = cnst.split(" = ")[1]
    if ' - ' in right:
        r1 = right.split(' - ')[0]
        r2 = right.split(' - ')[1]
        solver.add(getZ3(left) == getZ3(r1) - getZ3(r2))
    elif ' & ' in right:
        r1 = right.split(' & ')[0]
        r2 = right.split(' & ')[1]
        solver.add(getZ3(left) == getZ3(r1) & getZ3(r2))
    elif ' ^ ' in right:
        r1 = right.split(' ^ ')[0]
        r2 = right.split(' ^ ')[1]
        solver.add(getZ3(left) == getZ3(r1) ^ getZ3(r2))
    else:
        solver.add(getZ3(left) == getZ3(right))

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
        f = open(self.tainted[0][1], 'w')
        f.write(self.value)
        f.close()

        pinCmd = ['pin', '-t', 'confuzzer.so', '-tainted-input', self.getTainted(), '--']
        subprocess.call(pinCmd + self.program)

    def process(self):
        data = open('execution.dat').read().split('\n')
        branchStrings = []
        constraintStrings = []
        solver = z3.Solver()
        vrs = {}
        for i in range(32):
            vrs['$E%d' % i] = z3.BitVec('$E%d' % i, 32)
        for l in data:
            if l.startswith('br_'):
                bid = l.split(":")[0]
                instr = l.split(":")[1][1:].split(" - ")[0]
                var = l.split(":")[1][1:].split(" - ")[1]
                branchStrings.append((bid, asmInstruction(instr, var)))
            elif l.startswith('  '):
                var = l.split(":")[0].strip()
                if not var in vrs:
                    vrs[var] = z3.BitVec(var, 32)
                instr = l.split(":")[1][1:].split("(")[0].strip()
                eqtn = l.split(" - ")[-1].strip()
                constraintStrings.append((var, asmInstruction(instr, eqtn)))
        for (v,c) in constraintStrings:
            asmZ3(solver, vrs, c)
        for (b,c) in branchStrings:
            asmZ3(solver, vrs, c)
        #print solver.assertions()
        solver.check()
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
