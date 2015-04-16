#include "pin.H"
#include <sys/types.h>
#include <iostream>
#include <fstream>
#include <string>
#include <map>

std::map<ADDRINT, std::string> syscallNames;
std::map<REG, std::string> registerNames;

void StringifierSetup() {
  ifstream file("/usr/include/x86_64-linux-gnu/asm/unistd_64.h");
  if(file.is_open()) {
    string line;
    while(getline(file, line)) {
      if(line.find("define __NR") != string::npos) {
	line = line.substr(13);
	syscallNames[std::stoi(line.substr(line.find(" ")))] = line.substr(0, line.find(" "));
      }
    }
  }
  file.close();

  registerNames[REG_RDI] = "RDI";
  registerNames[REG_EDI] = "EDI";
  registerNames[REG_DI] = "DI";
  registerNames[REG_DIL] = "DIL";
  registerNames[REG_RSI] = "RSI";
  registerNames[REG_ESI] = "ESI";
  registerNames[REG_SI] = "SI";
  registerNames[REG_SIL] = "SIL";
  registerNames[REG_RBX] = "RBX";
  registerNames[REG_EBX] = "EBX";
  registerNames[REG_BX] = "BX";
  registerNames[REG_BL] = "BL";
  registerNames[REG_BH] = "BH";
  registerNames[REG_RDX] = "RDX";
  registerNames[REG_EDX] = "EDX";
  registerNames[REG_DX] = "DX";
  registerNames[REG_DL] = "DL";
  registerNames[REG_DH] = "DH";
  registerNames[REG_RCX] = "RCX";
  registerNames[REG_ECX] = "ECX";
  registerNames[REG_CX] = "CX";
  registerNames[REG_CL] = "CL";
  registerNames[REG_CH] = "CH";
  registerNames[REG_RAX] = "RAX";
  registerNames[REG_EAX] = "EAX";
  registerNames[REG_AX] = "AX";
  registerNames[REG_AL] = "AL";
  registerNames[REG_AH] = "AH";
  registerNames[REG_R8] = "R8";
  registerNames[REG_R8D] = "R8D";
  registerNames[REG_R8W] = "R8W";
  registerNames[REG_R8B] = "R8B";
  registerNames[REG_R9] = "R9";
  registerNames[REG_R9D] = "R9D";
  registerNames[REG_R9W] = "R9W";
  registerNames[REG_R9B] = "R9B";
  registerNames[REG_R10] = "R10";
  registerNames[REG_R10D] = "R10D";
  registerNames[REG_R10W] = "R10W";
  registerNames[REG_R10B] = "R10B";
  registerNames[REG_R11] = "R11";
  registerNames[REG_R11D] = "R11D";
  registerNames[REG_R11W] = "R11W";
  registerNames[REG_R11B] = "R11B";
  registerNames[REG_R12] = "R12";
  registerNames[REG_R12D] = "R12D";
  registerNames[REG_R12W] = "R12W";
  registerNames[REG_R12B] = "R12B";
  registerNames[REG_R13] = "R13";
  registerNames[REG_R13D] = "R13D";
  registerNames[REG_R13W] = "R13W";
  registerNames[REG_R13B] = "R13B";
  registerNames[REG_R14] = "R14";
  registerNames[REG_R14D] = "R14D";
  registerNames[REG_R14W] = "R14W";
  registerNames[REG_R14B] = "R14B";
  registerNames[REG_R15] = "R15";
  registerNames[REG_R15D] = "R15D";
  registerNames[REG_R15W] = "R15W";
  registerNames[REG_R15B] = "R15B";  
  registerNames[REG_RBP] = "RBP";
  registerNames[REG_EBP] = "EBP";
  registerNames[REG_BP] = "BP";
  registerNames[REG_RSP] = "RSP";
  registerNames[REG_ESP] = "ESP";
  registerNames[REG_SP] = "SP";
  registerNames[REG_EIP] = "EIP";
  registerNames[REG_RIP] = "RIP";
  registerNames[REG_IP] = "IP";
  registerNames[REG_RFLAGS] = "RFLAGS";
  registerNames[REG_EFLAGS] = "EFLAGS";
  registerNames[REG_FLAGS] = "FLAGS";
  registerNames[REG_SI] = "SI";
  registerNames[REG_DI] = "DI";

  registerNames[REG_XMM0] = "XMM0";
  registerNames[REG_XMM1] = "XMM1";
  registerNames[REG_XMM2] = "XMM2";
  registerNames[REG_XMM3] = "XMM3";
  registerNames[REG_XMM4] = "XMM4";
  registerNames[REG_XMM5] = "XMM5";
  registerNames[REG_XMM6] = "XMM6";
  registerNames[REG_XMM7] = "XMM7";
  registerNames[REG_XMM8] = "XMM8";
  registerNames[REG_XMM9] = "XMM9";
  registerNames[REG_XMM10] = "XMM10";
  registerNames[REG_XMM11] = "XMM11";
  registerNames[REG_XMM12] = "XMM12";
  registerNames[REG_XMM13] = "XMM13";
  registerNames[REG_XMM14] = "XMM14";
  registerNames[REG_XMM15] = "XMM15";
  
}

std::string SyscallName(ADDRINT num) {
  return syscallNames[num];
}

std::string RegisterName(REG reg) {
  return registerNames[reg];
}
