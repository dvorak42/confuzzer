#!/usr/bin/python

def asmBranch(instr, state):
    opc = instr.split(" ")[0]
    if opc == 'jnz':
        return state[::-1][6] != '0'
    elif opc == 'jz':
        return state[::-1][6] == '0'
    

def asmInstruction(instr, eqtn):
    opc = instr.split(" ")[0]
    if instr.startswith('External Taint'):
        src = eqtn.split(' -> ')[0]
        dst = eqtn.split(' -> ')[1].split(' ')[0]
        return '%s = %s' % (dst, '$E%s' % src.replace('EXT_', ''))
    if opc == 'jnz':
        return '%s != 0' % eqtn.split(' ')[0]
    elif opc == 'jz':
        return '%s == 0' % eqtn.split(' ')[0]
    elif opc.startswith('mov') or opc == 'push' or opc == 'pop':
        src = eqtn.split(' -> ')[0]
        dst = eqtn.split(' -> ')[1].split(' ')[0]
        return '%s = %s' % (dst, src)
    elif opc == 'cmp':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1].split(' ')[0]
        return '%s = %s - %s' % (dst, src2, src1)
    elif opc == 'test':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1].split(' ')[0]
        return '%s = %s & %s' % (dst, src1, src2)
    elif opc == 'sub':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1].split(' ')[0]
        return '%s = %s - %s' % (dst, src1, src2)
    elif opc == 'add':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1].split(' ')[0]
        return '%s = %s + %s' % (dst, src1, src2)
    elif opc == 'xor':
        src1 = eqtn.split(' -> ')[0].split(' + ')[0]
        src2 = eqtn.split(' -> ')[0].split(' + ')[1]
        dst = eqtn.split(' -> ')[1].split(' ')[0]
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
    elif ' + ' in right:
        r1 = right.split(' + ')[0]
        r2 = right.split(' + ')[1]
        solver.add(getZ3(left) == getZ3(r1) + getZ3(r2))
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
