#include "pin.H"
#include <list>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include "stringifier.h"

std::list<UINT64> taintedAddress;
std::list<REG> taintedRegister;

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

int endIndex(int index) {
  return 5 * (index/5 + 1);
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

std::string printTaint() {
  std::stringstream state;
  
  state << "Tainted Addresses:\n\t";
  for(list<UINT64>::iterator i = taintedAddress.begin(); i != taintedAddress.end(); i++) {
    state << "0x" << std::hex << *i << ", ";
  }
  
  state << "\nTainted Registers:\n\t";
  for(list<REG>::iterator i = taintedRegister.begin(); i != taintedRegister.end(); i++) {
    state << RegisterName(*i) << ", ";
  }
  return state.str();
}

void taintMemToReg(UINT64 instructionAddr, std::string instruction, UINT64 memAddr, REG reg) {
  if(!isMemoryTainted(memAddr)) {
    removeRegisterTaint(reg);
    return;
  }
  if(isRegisterTainted(reg))
    return;
  //std::cout << "[" << std::hex << instructionAddr << "] " << instruction << std::endl;
  //std::cout << "[" << std::hex << instructionAddr << "] Tainting address 0x" << std::hex << memAddr << " to register " << RegisterName(reg) << std::endl;
  addRegisterTaint(reg);
  //std::cout << printTaint() << std::endl;
}

void taintRegToMem(UINT64 instructionAddr, std::string instruction, REG reg, UINT64 memAddr) {
  if(!isRegisterTainted(reg)) {
    removeMemoryTaint(memAddr);
    return;
  }
  if(isMemoryTainted(memAddr))
    return;
  //std::cout << "[" << std::hex << instructionAddr << "] " << instruction << std::endl;
  //std::cout << "[" << std::hex << instructionAddr << "] Tainting register " << RegisterName(reg) << " to address 0x" << std::hex << memAddr << std::endl;
  addMemoryTaint(memAddr);
  //std::cout << printTaint() << std::endl;
}

void taintRegToReg(UINT64 instructionAddr, std::string instruction, REG regSrc, REG regDst) {
  if(!isRegisterTainted(regSrc)) {
    removeRegisterTaint(regDst);
    return;
  }
  //std::cout << "[" << std::hex << instructionAddr << "] " << instruction << std::endl;
  if(isRegisterTainted(regDst))
    return;
  //std::cout << "[" << std::hex << instructionAddr << "] Tainting register " << RegisterName(regSrc) << " to register " << RegisterName(regDst) << std::endl;
  addRegisterTaint(regDst);
  //std::cout << printTaint() << std::endl;
}

void taintReg2ToReg(UINT64 instructionAddr, std::string instruction, REG regSrc1, REG regSrc2, REG regDst) {
  if(!isRegisterTainted(regSrc1) && !isRegisterTainted(regSrc2)) {
    removeRegisterTaint(regDst);
    return;
  }
  //std::cout << "[" << std::hex << instructionAddr << "] " << instruction << std::endl;
  if(isRegisterTainted(regDst))
    return;
  //std::cout << "[" << std::hex << instructionAddr << "] Tainting register " << RegisterName(regSrc) << " to register " << RegisterName(regDst) << std::endl;
  addRegisterTaint(regDst);
  //std::cout << printTaint() << std::endl;
}
