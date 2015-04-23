#!/usr/bin/python
import z3

def asmBranch(instr, state):
    opc, _ = instr.split(" ")
    rf = state[::-1]
    if opc == 'jnz':
        return rf[6] != '0'
    elif opc == 'jz':
        return rf[6] == '0'
    elif opc == 'jl':
        return rf[7] != rf[11]
    

def asmInstruction(instr, eqtn):
    opc,rest = instr.split(" ", 1)
    src = eqtn
    dst = None
    src1 = None
    src2 = None

    if 'RFLAGS_' in eqtn and 'RFLAGS_0' not in eqtn:
        return None

    if ' @> ' in eqtn:
        dst,src = eqtn.split(' @> ')
        return '%s = %s' % (dst, src)

    if ' -> ' in eqtn:
        src, dst = eqtn.split(' -> ')

    if ' + ' in src:
        src1, src2 = src.split(' + ')

    if instr.startswith('External Taint'):
        return '%s = %s' % (dst, '$E%s' % src.replace('EXT_', ''))
    elif opc == 'jnz':
        return '%s != 0' % src
    elif opc == 'jz':
        return '%s == 0' % src
    elif opc == 'jl':
        return '%s < 0' % src
    elif opc == 'bsf':
        return '%s <- %s' % (dst, src)
    elif opc.startswith('mov') or opc == 'push' or opc == 'pop' or opc == 'pmovmskb':
        return '%s = %s' % (dst, src)
    elif opc == 'pslldq':
        shift = rest.split(', ')[1]
        return '%s = %s << %s' % (dst, src1, shift)
    elif (opc == 'pcmpeqb' or opc == 'cmp') and src1:
        return '%s = %s - %s' % (dst, src2, src1)
    elif opc == 'test' and src1:
        return '%s = %s & %s' % (dst, src1, src2)
    elif (opc == 'psubb' or opc == 'sub') and src1:
        return '%s = %s - %s' % (dst, src1, src2)
    elif opc == 'add' and src1:
        return '%s = %s + %s' % (dst, src1, src2)
    elif opc == 'xor' and src1:
        return '%s = %s ^ %s' % (dst, src1, src2)
        
    print "Unknown instruction: %s (%s)" % (instr, eqtn)
    return ""

def asmZ3(solver, vrs, cnst, invert=False):
    def getZ3(v):
        v = v.strip()
        if v in vrs:
            return vrs[v]
        elif v.startswith('0x'):
            return int(v[2:], 16)
        else:
            try:
                return int(v, 16)
            except:
                vrs[v] = z3.BitVec(v, 32)
                return vrs[v]
    def z3ify(vs):
        return [getZ3(i) for i in vs]


    term = None

    if ' <- ' in cnst:
        l,r = z3ify(cnst.split(' <- '))
        term = l == r != 0
    if ' == ' in cnst:
        l,r = z3ify(cnst.split(' == '))
        term = l == r
    elif ' != ' in cnst:
        l,r = z3ify(cnst.split(' != '))
        term = l != r
    elif ' < ' in cnst:
        l,r = z3ify(cnst.split(' < '))
        term = l < r
    elif ' <= ' in cnst:
        l,r = z3ify(cnst.split(' <= '))
        term = l <= r
    elif ' >= ' in cnst:
        l,r = z3ify(cnst.split(' >= '))
        term = l >= r
    elif ' > ' in cnst:
        l,r = z3ify(cnst.split(' > '))
        term = l > r
    elif ' = ' in cnst:
        l,r = cnst.split(' = ')
        l = getZ3(l)
        if ' - ' in r:
            r1,r2 = z3ify(r.split(' - '))
            term = l == r1 - r2
        elif ' + ' in r:
            r1,r2 = z3ify(r.split(' + '))
            term = l == r1 + r2
        elif ' & ' in r:
            r1,r2 = z3ify(r.split(' & '))
            term = l == r1 & r2
        elif ' | ' in r:
            r1,r2 = z3ify(r.split(' | '))
            term = l == r1 | r2
        elif ' ^ ' in r:
            r1,r2 = z3ify(r.split(' ^ '))
            term = l == r1 ^ r2
        elif ' << ' in r:
            r1,r2 = z3ify(r.split(' << '))
            term = l == r1 << r2
        elif not ' ' in r.strip():
            term = l == getZ3(r)

    if term:
        if invert:
            return solver.add(z3.Not(term))
        return solver.add(term)

    print "Unknown Constraint: %s" % cnst
