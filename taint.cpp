#include "pin.H"
#include <list>
#include <map>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include "stringifier.h"

std::list<UINT64> taintedAddress;
std::list<REG> taintedRegister;
std::map<UINT64, UINT64> addressID;
std::map<REG, UINT64> registerID;
std::map<string, string> taintEquations;


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
  REG_RBP , REG_EBP , REG_BP  , (REG)0  , (REG)0, 
  REG_RSP , REG_ESP , REG_SP  , (REG)0  , (REG)0, 
  REG_RIP , REG_EIP , REG_IP  , (REG)0  , (REG)0, 
  REG_RFLAGS, REG_EFLAGS, REG_FLAGS, (REG)0, (REG)0, 
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

string getValue(CONTEXT* ctxt, REG reg) {
  UINT8 val;
  PIN_GetContextRegval(ctxt, reg, (UINT8*)&val);
  std::stringstream stream;
  stream << "0x" << std::hex << std::setfill('0') << int(val);
  return std::string(stream.str());
}

string getValue(CONTEXT* ctxt, UINT64 addr) {
  char buffer[1];
  PIN_SafeCopy(buffer, (ADDRINT*)addr, 1);
  std::stringstream stream;
  stream << "0x" << std::hex << std::setfill('0') << int(buffer[0]);
  return std::string(stream.str());
}

int registerIndex(REG reg) {
  for(int i = 0; i < (int)(sizeof(regs) / sizeof(REG)); i++) {
    if(regs[i] == reg)
      return i;
  }
  return -1;
}

REG baseRegister(int index) {
  return regs[index / 5 * 5];
}

REG baseRegister(REG reg) {
  return regs[registerIndex(reg) / 5 * 5];
}

int endIndex(int index) {
  return 5 * (index/5 + 1);
}

string getRegID(REG br) {
  return RegisterName(br) + "_" + std::to_string(registerID[br]);
}

string getMemID(UINT64 memAddr) {
  return "MEM_" + hexifyAddr(memAddr) + "_" + std::to_string(addressID[memAddr]);
}

string getNextRegID(REG br) {
  return RegisterName(br) + "_" + std::to_string(registerID[br]+1);
}

string getNextMemID(UINT64 memAddr) {
  return "MEM_" + hexifyAddr(memAddr) + "_" + std::to_string(addressID[memAddr]+1);
}

bool isRegisterTainted(REG reg) {
  REG breg = baseRegister(registerIndex(reg));
  for(list<REG>::iterator i = taintedRegister.begin(); i != taintedRegister.end(); i++) {
    if(breg == *i)
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

void addRegisterTaint(REG reg) {
  int index = registerIndex(reg);
  if(index == -1)
    return;
  if(isRegisterTainted(reg))
    return;
  taintedRegister.push_back(baseRegister(index));
}

void removeRegisterTaint(REG reg) {
  int index = registerIndex(reg);
  if(index == -1)
    return;
  taintedRegister.remove(baseRegister(index));
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
  taintEquations[getMemID(addr)] = "External Taint Offset " + offs + " " + "(EXT_" + offs + "->" + getMemID(addr) + ") - EXT_" + offs + " -> " + getMemID(addr);
}


std::string printTaint() {
  std::stringstream state;
  
  //state << "Tainted Addresses:\n\t";
  //for(list<UINT64>::iterator i = taintedAddress.begin(); i != taintedAddress.end(); i++) {
  //  state << "0x" << std::hex << *i << " [" << addressID[*i] << "], ";
  //}
  
  state << "\nTainted Registers:\n\t";
  for(list<REG>::iterator i = taintedRegister.begin(); i != taintedRegister.end(); i++) {
    state << RegisterName(*i) << " [" << registerID[*i] << "], ";
  }

  state << "\nEquations:\n";
  typedef std::map<std::string, std::string>::iterator m_type;
  for(m_type iterator = taintEquations.begin(); iterator != taintEquations.end(); iterator++) {
    state << "\t" << iterator->first << ": " << iterator->second << std::endl;
  }
  return state.str();
}

std::string getConstraints() {
  std::stringstream constraints;
  
  typedef std::map<std::string, std::string>::iterator m_type;
  for(m_type iterator = taintEquations.begin(); iterator != taintEquations.end(); iterator++) {
    constraints << "  " << iterator->first << ": " << iterator->second << std::endl;
  }
  return constraints.str();
}

void taintMemToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, UINT64 memAddr, REG reg) {
  if(!isMemoryTainted(memAddr)) {
    removeRegisterTaint(reg);
    return;
  }
  REG br = baseRegister(reg);
  if(!registerID.count(br)) {
    registerID[br] = 0;
  }
  taintEquations[getNextRegID(br)] = instruction + " " + "(" + getValue(ctxt, memAddr) + "->" + getNextRegID(br) + ") - " + getMemID(memAddr) + " -> " + getNextRegID(br);
  registerID[br] = registerID[br] + 1;
  if(isRegisterTainted(reg))
    return;
  addRegisterTaint(reg);
}

void taintRegToMem(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG reg, UINT64 memAddr) {
  if(!isRegisterTainted(reg)) {
    removeMemoryTaint(memAddr);
    return;
  }
  if(!addressID.count(memAddr)) {
    addressID[memAddr] = 0;
  }
  REG br = baseRegister(reg);

  taintEquations[getNextMemID(memAddr)] = instruction + " " + "(" + getValue(ctxt, br) + "->" + getNextMemID(memAddr) + ") - " + getRegID(br) + " -> " + getNextMemID(memAddr);
  addressID[memAddr] = addressID[memAddr] + 1;

  if(isMemoryTainted(memAddr))
    return;
  addMemoryTaint(memAddr);
}

void taintRegToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regSrc, REG regDst) {
  if(!isRegisterTainted(regSrc)) {
    removeRegisterTaint(regDst);
    return;
  }
  REG brSrc = baseRegister(regSrc);
  REG brDst = baseRegister(regDst);
  if(!registerID.count(brDst)) {
    registerID[brDst] = 0;
  }
  taintEquations[getNextRegID(brDst)] = instruction + " " + "(" + getValue(ctxt, brSrc) + "->" + getNextRegID(brDst) + ") - " + getRegID(brSrc) + " -> " + getNextRegID(brDst);
  registerID[brDst] = registerID[brDst] + 1;
  if(isRegisterTainted(regDst))
    return;
  addRegisterTaint(regDst);
}

void taintRegConstantToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regSrc, ADDRINT cnst, REG regDst) {
  if(!isRegisterTainted(regSrc)) {
    removeRegisterTaint(regDst);
    return;
  }
  REG brSrc = baseRegister(regSrc);
  REG brDst = baseRegister(regDst);
  if(!registerID.count(brDst)) {
    registerID[brDst] = 0;
  }
  string ch = hexify(cnst);
  taintEquations[getNextRegID(brDst)] = instruction + " " + "(" + getValue(ctxt, brSrc) + "+" +  ch + "->" + getNextRegID(brDst) + ") - " + getRegID(brSrc) + " + " + ch + " -> " + getNextRegID(brDst);
  registerID[brDst] = registerID[brDst] + 1;
  if(isRegisterTainted(regDst))
    return;
  addRegisterTaint(regDst);
}

void taintConstantToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regDst) {
  removeRegisterTaint(regDst);
  return;
}

void taintReg2ToReg(CONTEXT* ctxt, UINT64 instructionAddr, std::string instruction, REG regSrc1, REG regSrc2, REG regDst) {
  if(!isRegisterTainted(regSrc1) && !isRegisterTainted(regSrc2)) {
    removeRegisterTaint(regDst);
    return;
  }
  REG brSrc1 = baseRegister(regSrc1);
  REG brSrc2 = baseRegister(regSrc2);
  REG brDst = baseRegister(regDst);
  if(!registerID.count(brDst)) {
    registerID[brDst] = 0;
  }
  if(isRegisterTainted(regSrc1) && isRegisterTainted(regSrc2)) {
    taintEquations[getNextRegID(brDst)] = instruction + " " + "(" + getValue(ctxt, brSrc1) + "+" + getValue(ctxt, brSrc2) + "->" + getNextRegID(brDst) + ") - " + getRegID(brSrc1) + + " + " + getRegID(brSrc2) + " -> " + getNextRegID(brDst);
  } else if(isRegisterTainted(regSrc1)) {
    taintEquations[getNextRegID(brDst)] = instruction + " " + "(" + getValue(ctxt, brSrc1) + "+" + getValue(ctxt, brSrc2) + "->" + getNextRegID(brDst) + ") - " + getRegID(brSrc1) + + " + " + getValue(ctxt, brSrc2) + " -> " + getNextRegID(brDst);
  } else {
    taintEquations[getNextRegID(brDst)] = instruction + " " + "(" + getValue(ctxt, brSrc1) + "+" + getValue(ctxt, brSrc2) + "->" + getNextRegID(brDst) + ") - " + getValue(ctxt, brSrc1) + + " + " + getRegID(brSrc2) + " -> " + getNextRegID(brDst);
  }
  registerID[brDst] = registerID[brDst] + 1;
  if(isRegisterTainted(regDst))
    return;
  addRegisterTaint(regDst);
}
