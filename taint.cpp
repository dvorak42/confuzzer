#include "pin.H"
#include <list>
#include <map>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include "stringifier.h"

struct RegChunk {
  REG reg;
  UINT32 chunk;

  bool operator<(const RegChunk& other) const {
    if(this->reg < other.reg)
      return true;
    else if(this->reg > other.reg)
      return false;
    if(this->chunk < other.chunk)
      return true;
    return false;
  }

  bool operator==(const RegChunk& other) const {
    bool r = this->reg == other.reg && this->chunk == other.chunk;
    return r;
  }
};

std::list<string> taintEquations;
std::list<UINT64> taintedAddress;
std::map<UINT64, UINT64> addressID;
std::map<RegChunk, UINT64> registerID;
std::list<RegChunk> taintedRegister;

static REG regs[] = {
  REG_RDI , REG_EDI , REG_DI  , REG_DIL , (REG)0,
  REG_RSI , REG_ESI , REG_SI  , REG_SIL , (REG)0,
  REG_RBX , REG_EBX , REG_BX  , REG_BL  , REG_BH,
  REG_RDX , REG_EDX , REG_DX  , REG_DL  , REG_DH,
  REG_RCX , REG_ECX , REG_CX  , REG_CL  , REG_CH,
  REG_RAX , REG_EAX , REG_AX  , REG_AL  , REG_AH,
  REG_R8  , REG_R8D , REG_R8W , REG_R8B , (REG)0,
  REG_R9  , REG_R9D , REG_R9W , REG_R9B , (REG)0,
  REG_R10 , REG_R10D, REG_R10W, REG_R10B, (REG)0,
  REG_R11 , REG_R11D, REG_R11W, REG_R11B, (REG)0,
  REG_R12 , REG_R12D, REG_R12W, REG_R12B, (REG)0,
  REG_R13 , REG_R13D, REG_R13W, REG_R13B, (REG)0,
  REG_R14 , REG_R14D, REG_R14W, REG_R14B, (REG)0,
  REG_R15 , REG_R15D, REG_R15W, REG_R15B, (REG)0,
  REG_RBP , REG_EBP , REG_BP  , REG_BPL , (REG)0, 
  REG_RSP , REG_ESP , REG_SP  , REG_SPL , (REG)0, 
  REG_RIP , REG_EIP , REG_IP  , (REG)0  , (REG)0, 
  REG_RFLAGS, REG_EFLAGS, REG_FLAGS, (REG)0, (REG)0, 
  REG_XMM0, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM1, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM2, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM3, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM4, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM5, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM6, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM7, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM8, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM9, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM10, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM11, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM12, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM13, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM14, (REG)0  , (REG)0  , (REG)0  , (REG)0,
  REG_XMM15, (REG)0  , (REG)0  , (REG)0  , (REG)0,
};

string hexifyAddr(UINT64 v) {
  std::stringstream stream;
  stream << std::setw(8) << std::hex << std::setfill('0') << v;
  return stream.str();
}

string hexify(UINT64 v) {
  std::stringstream stream;
  stream << "0x" << std::hex << v;
  return stream.str();
}

// TODO: Add size of target for multiple
string getValue(CONTEXT* ctxt, RegChunk rc) {
  PIN_REGISTER val;
  PIN_GetContextRegval(ctxt, rc.reg, (UINT8*)&val);

  std::stringstream stream;
  stream << "0x" << std::hex;
  stream << std::setw(2) << std::setfill('0') << int(val.byte[rc.chunk]);
  return std::string(stream.str());
}

string getValue(CONTEXT* ctxt, UINT64 addr) {
  char buffer[1];
  PIN_SafeCopy(buffer, (ADDRINT*)addr, 1);
  std::stringstream stream;
  stream << "0x" << std::hex;
  stream << std::setw(2) << std::setfill('0') << int(buffer[0]);
  return std::string(stream.str());
}

REG baseRegister(REG reg) {
  for(int i = 0; i < (int)(sizeof(regs) / sizeof(REG)); i++) {
    if(regs[i] == reg)
      return regs[i / 5 * 5];
  }
  std::cout << "Unknown Register: " << reg << " - " << RegisterName(reg) << std::endl;
  return regs[0];
}

UINT32 registerSize(REG reg) {
  return REG_Size(reg);
}

string getRegID(REG reg) {
  RegChunk rc = {baseRegister(reg), 0};
  return RegisterName(rc.reg) + "_" + std::to_string(rc.chunk) + "_" + std::to_string(registerID[rc]);
}

string getRegID(RegChunk rc) {
  return RegisterName(rc.reg) + "_" + std::to_string(rc.chunk) + "_" + std::to_string(registerID[rc]);
}

string getNextRegID(RegChunk rc) {
  return RegisterName(rc.reg) + "_" + std::to_string(rc.chunk) + "_" + std::to_string(registerID[rc]+1);
}

string getMemID(UINT64 memAddr) {
  return "MEM_" + hexifyAddr(memAddr) + "_" + std::to_string(addressID[memAddr]);
}

string getNextMemID(UINT64 memAddr) {
  return "MEM_" + hexifyAddr(memAddr) + "_" + std::to_string(addressID[memAddr]+1);
}

bool isRegisterTainted(REG reg) {
  REG breg = baseRegister(reg);
  for(list<RegChunk>::iterator i = taintedRegister.begin(); i != taintedRegister.end(); i++) {
    if(breg == (*i).reg)
      return true;
  }
  return false;
}

bool isRegisterTainted(RegChunk reg) {
  for(list<RegChunk>::iterator i = taintedRegister.begin(); i != taintedRegister.end(); i++) {
    if(reg.reg == (*i).reg && reg.chunk == (*i).chunk)
      return true;
  }
  return false;
}

bool isMemoryTainted(UINT64 addr) {
  for(list<UINT64>::iterator i = taintedAddress.begin(); i != taintedAddress.end(); i++) {
    if(addr == *i)
      return true;
  }
  return false;
}

void addRegisterTaint(RegChunk rc) {
  if(!isRegisterTainted(rc))
    taintedRegister.push_back(rc);
}

void removeRegisterTaint(RegChunk rc) {
  if(isRegisterTainted(rc))
    taintedRegister.remove(rc);
}

void addMemoryTaint(UINT64 addr) {
  taintedAddress.push_back(addr);
}

void removeMemoryTaint(UINT64 addr) {
  taintedAddress.remove(addr);
}

void addExternalTaint(UINT64 addr, UINT64 extOffset) {
  taintedAddress.push_back(addr);

  if(!addressID.count(addr)) {
    addressID[addr] = 0;
  }
  addressID[addr] = addressID[addr] + 1;
  string offs = std::to_string(extOffset);
  taintEquations.push_back(getMemID(addr) + ": " + "External Taint ::: EXT_" + offs + " -> " + getMemID(addr));
}


std::string printTaint() {
  std::stringstream state;
  
  //state << "Tainted Addresses:\n\t";
  //for(list<UINT64>::iterator i = taintedAddress.begin(); i != taintedAddress.end(); i++) {
  //  state << "0x" << std::hex << *i << " [" << addressID[*i] << "], ";
  //}
  
  state << "\nTainted Registers:\n\t";
  for(list<RegChunk>::iterator i = taintedRegister.begin(); i != taintedRegister.end(); i++) {
    state << RegisterName((*i).reg) << "_" << std::to_string((*i).chunk) << " [" << registerID[*i] << "], ";
  }

  state << "\nEquations:\n";
  typedef std::map<std::string, std::string>::iterator m_type;
  for(list<string>::iterator it = taintEquations.begin(); it != taintEquations.end(); it++) {
    state << "\t" << *it << std::endl;
  }
  return state.str();
}

std::string getConstraints() {
  std::stringstream constraints;
  
  typedef std::map<std::string, std::string>::iterator m_type;
  for(list<string>::iterator it = taintEquations.begin(); it != taintEquations.end(); it++) {
    constraints << "  " << *it << std::endl;
  }
  return constraints.str();
}

void taintMemToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, UINT64 memAddr, REG reg, UINT32 memSize) {
  REG dstBase = baseRegister(reg);
  UINT32 dstSize = registerSize(reg);
  UINT32 regSize = registerSize(dstBase);
  bool tainted = false;
  for(UINT32 off = 0; off < regSize; off++) {
    RegChunk dstC = {dstBase, off};
    UINT64 mA = memAddr + off;

    if(!registerID.count(dstC)) {
      registerID[dstC] = 0;
    }

    string dstID = getRegID(dstC);
    string dstNI = getNextRegID(dstC);
    string eqtn;

    if(off < memSize && off < dstSize) {
      if(isMemoryTainted(mA)) {
	tainted = true;
	eqtn = instruction + " ::: " + getMemID(mA) + " -> " + dstNI;
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, mA) + " -> " + dstNI;	
      }
    } else {
      if(isRegisterTainted(dstC)) {
	eqtn = instruction + " ::: " + dstID + " @> " + dstNI;	
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, dstC) + " @> " + dstNI;	
      }
    }
    if(tainted) {
      taintEquations.push_back(dstNI + ": " + eqtn);
      addRegisterTaint(dstC);
    } else {
      removeRegisterTaint(dstC);
    }
  }

  if(tainted) {
    for(UINT32 off = 0; off < regSize; off++) {
      RegChunk dstC = {dstBase, off};
      registerID[dstC] = registerID[dstC] + 1;
    }
  }
}

void taintRegToMem(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG reg, UINT64 memAddr, UINT32 memSize) {
  REG srcBase = baseRegister(reg);
  UINT32 dstSize = memSize;
  bool tainted = false;
  for(UINT32 off = 0; off < dstSize; off++) {
    RegChunk srcC = {srcBase, off};
    UINT64 mA = memAddr + off;

    if(!addressID.count(mA)) {
      addressID[mA] = 0;
    }

    string dstID = getMemID(mA);
    string dstNI = getNextMemID(mA);
    string eqtn;

    if(isRegisterTainted(srcC)) {
      tainted = true;
      eqtn = instruction + " ::: " + getRegID(srcC) + " -> " + dstNI;
    }

    if(tainted) {
      taintEquations.push_back(dstNI + ": " + eqtn);
      addMemoryTaint(mA);
    } else {
      removeMemoryTaint(mA);
    }
  }
  if(tainted) {
    for(UINT32 off = 0; off < dstSize; off++) {
      addressID[memAddr + off] += 1;
    }
  }
}

void taintRegToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regSrc, REG regDst) {
  REG srcBase = baseRegister(regSrc);
  UINT32 srcSize = registerSize(regSrc);
  REG dstBase = baseRegister(regDst);
  UINT32 dstSize = registerSize(regDst);
  UINT32 regSize = registerSize(dstBase);
  bool tainted = false;
  for(UINT32 off = 0; off < regSize; off++) {
    RegChunk srcC = {srcBase, off};
    RegChunk dstC = {dstBase, off};

    if(!registerID.count(dstC)) {
      registerID[dstC] = 0;
    }

    string dstID = getRegID(dstC);
    string dstNI = getNextRegID(dstC);
    string eqtn;

    if(off < dstSize) {
      if(isRegisterTainted(srcC)) {
	tainted = true;
	eqtn = instruction + " ::: " + getRegID(srcC) + " -> " + dstNI;
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, srcC) + " -> " + dstNI;
      }
    } else {
      if(isRegisterTainted(dstC)) {
	eqtn = instruction + " ::: " + dstID + " @> " + dstNI;	
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, dstC) + " @> " + dstNI;	
      }
    }

    if(tainted) {
      taintEquations.push_back(dstNI + ": " + eqtn);
      addRegisterTaint(dstC);
    } else {
      removeRegisterTaint(dstC);
    }
  }

  if(tainted) {
    for(UINT32 off = 0; off < regSize; off++) {
      RegChunk dstC = {dstBase, off};
      registerID[dstC] = registerID[dstC] + 1;
    }
  }
}

void taintRegConstantToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regSrc, ADDRINT cnst, REG regDst) {
  REG srcBase = baseRegister(regSrc);
  UINT32 srcSize = registerSize(regSrc);
  REG dstBase = baseRegister(regDst);
  UINT32 dstSize = registerSize(regDst);
  UINT32 regSize = registerSize(dstBase);
  bool tainted = false;
  for(UINT32 off = 0; off < regSize; off++) {
    RegChunk srcC = {srcBase, off};
    RegChunk dstC = {dstBase, off};
    string ch = hexify(cnst % 256);
    cnst /= 256;

    if(!registerID.count(dstC)) {
      registerID[dstC] = 0;
    }

    string dstID = getRegID(dstC);
    string dstNI = getNextRegID(dstC);
    string eqtn;

    if(off < dstSize) {
      if(isRegisterTainted(srcC)) {
	tainted = true;
	eqtn = instruction + " ::: " + getRegID(srcC) + " + " + ch + " -> " + dstNI;
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, srcC) + " + " + ch + " -> " + dstNI;
      }
    } else {
      if(isRegisterTainted(dstC)) {
	eqtn = instruction + " ::: " + dstID + " @> " + dstNI;	
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, dstC) + " @> " + dstNI;	
      }
    }

    if(tainted) {
      taintEquations.push_back(dstNI + ": " + eqtn);
      addRegisterTaint(dstC);
    } else {
      removeRegisterTaint(dstC);
    }
  }

  if(tainted) {
    for(UINT32 off = 0; off < regSize; off++) {
      RegChunk dstC = {dstBase, off};
      registerID[dstC] = registerID[dstC] + 1;
    }
  }
}

void taintConstantToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regDst) {
  REG dstBase = baseRegister(regDst);
  UINT32 dstSize = registerSize(regDst);
  UINT32 regSize = registerSize(dstBase);
  bool tainted = false;
  for(UINT32 off = 0; off < regSize; off++) {
    RegChunk dstC = {dstBase, off};
    removeRegisterTaint(dstC);
  }
}

void taintReg2ToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regSrc1, REG regSrc2, REG regDst) {
  REG sc1Base = baseRegister(regSrc1);
  UINT32 sc1Size = registerSize(regSrc1);
  REG sc2Base = baseRegister(regSrc2);
  UINT32 sc2Size = registerSize(regSrc2);
  REG dstBase = baseRegister(regDst);
  UINT32 dstSize = registerSize(regDst);
  UINT32 regSize = registerSize(dstBase);
  bool tainted = false;
  for(UINT32 off = 0; off < regSize; off++) {
    RegChunk sc1C = {sc1Base, off};
    RegChunk sc2C = {sc2Base, off};
    RegChunk dstC = {dstBase, off};

    if(!registerID.count(dstC)) {
      registerID[dstC] = 0;
    }

    string dstID = getRegID(dstC);
    string dstNI = getNextRegID(dstC);
    string eqtn;

    if(off < dstSize) {
      if(isRegisterTainted(sc1C) || isRegisterTainted(sc2C)) {
	tainted = true;
	if(!isRegisterTainted(sc1C)) {
	  eqtn = instruction + " ::: " + getValue(ctxt, sc1C) + " + " + getRegID(sc2C) + " -> " + dstNI;
	} else if(!isRegisterTainted(sc2C)) {
	  eqtn = instruction + " ::: " + getRegID(sc1C) + " + " + getValue(ctxt, sc2C) + " -> " + dstNI;
	} else {
	  eqtn = instruction + " ::: " + getRegID(sc1C) + " + " + getRegID(sc2C) + " -> " + dstNI;
	}
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, sc1C) + " + " + getValue(ctxt, sc2C) + " -> " + dstNI;
      }
    } else {
      if(isRegisterTainted(dstC)) {
	eqtn = instruction + " ::: " + dstID + " @> " + dstNI;	
      } else {
	eqtn = instruction + " ::: " + getValue(ctxt, dstC) + " @> " + dstNI;	
      }
    }

    if(tainted) {
      taintEquations.push_back(dstNI + ": " + eqtn);
      addRegisterTaint(dstC);
    } else {
      removeRegisterTaint(dstC);
    }
  }

  if(tainted) {
    for(UINT32 off = 0; off < regSize; off++) {
      RegChunk dstC = {dstBase, off};
      registerID[dstC] = registerID[dstC] + 1;
    }
  }
}
