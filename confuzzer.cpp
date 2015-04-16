#include <asm/unistd.h>
#include <bitset>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
#include <list>
#include "pin.H"

#include "stringifier.h"
#include "taint.h"

KNOB<std::string> TaintedInput(KNOB_MODE_WRITEONCE, "pintool", "tainted-input", "NONE", "Tainted Inputs");

void instrument(INS, void*);
void enterSyscall(THREADID, CONTEXT*, SYSCALL_STANDARD, void*);
void exitSyscall(THREADID, CONTEXT*, SYSCALL_STANDARD, void*);
void finalize(INT32, void*);

bool crashed = false;
bool catchSegfault(THREADID tid, INT32 sig, CONTEXT *ctxt, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
  crashed = true;
  return true;
}

int main(int argc, char* argv[]) {
  if(PIN_Init(argc, argv)) {
    std::cout << "Invalid arguments for " << argv[0] << std::endl;
    return -1;
  }

  std::cerr << "Starting Execution" << std::endl;

  StringifierSetup();

  PIN_SetSyntaxIntel();
  PIN_InitSymbols();

  PIN_InterceptSignal(SIGSEGV, catchSegfault, 0);
  INS_AddInstrumentFunction(instrument, 0);
  PIN_AddSyscallEntryFunction(enterSyscall, 0);
  PIN_AddSyscallExitFunction(exitSyscall, 0);
  PIN_AddFiniFunction(finalize, 0);

  PIN_StartProgram();

  std::cerr << "Completed Execution" << std::endl;
  return 0;
}

void trackInstruction(UINT64 addr, std::string instr) {
  //std::cout << "0x" << std::hex << addr << " - " << instr << std::endl;
  //std::cout << printTaint() << std::endl;
}

UINT64 branchID = 0;
std::list<string> branchData;

void trackJump(CONTEXT* ctxt, UINT64 addr, std::string instr) {
  if(isRegisterTainted(REG_RFLAGS) || isRegisterTainted(REG_EFLAGS) || isRegisterTainted(REG_FLAGS)) {
    //std::cout << "Tainted Jump: " << std::hex << addr << " - " << instr << " (" << getRegID(REG_RFLAGS) << ")" <<std::endl;
    //std::cout << printTaint() << std::endl;

    branchID += 1;

    // branchID (ADDRESS - INSTRUCTION) = MAIN_CONSTRAINT
    // CONSTRAINTS

    std::stringstream branch;
    branch << "br_" << std::setw(8) << std::hex << std::setfill('0') << addr << "_" << branchID;
    branch << ": " << instr;

    UINT8 val;
    PIN_GetContextRegval(ctxt, REG_RFLAGS, (UINT8*)&val);
    std::stringstream stream;
    std::bitset<16> x(val);
    stream << x;
    branch << " (" << stream.str() << ")";
    branch << " - " << getRegID(REG_RFLAGS) << std::endl;      

    // if(instr.compare(0, 3, string("jnz")) == 0) {
    //   branch << " - " << getRegID(REG_RFLAGS) << "_JNZ" << std::endl;      
    // } else if(instr.compare(0, 2, string("jz")) == 0) {
    //   branch << " - " << getRegID(REG_RFLAGS) << "_JZ" << std::endl;      
    // } else {
    //   std::cerr << "Unknown Jump: " << instr.substr(0, instr.find(" ")) << std::endl;
    // }

    //branch << getConstraints() << std::endl;
    branchData.push_back(branch.str());
  }
}

void trackPredicate(CONTEXT* ctxt, UINT64 addr, std::string instr) {
  if(isRegisterTainted(REG_RFLAGS) || isRegisterTainted(REG_EFLAGS) || isRegisterTainted(REG_FLAGS)) {
    //std::cout << "Tainted Jump: " << std::hex << addr << " - " << instr << " (" << getRegID(REG_RFLAGS) << ")" <<std::endl;
    //std::cout << printTaint() << std::endl;

    branchID += 1;

    // branchID (ADDRESS - INSTRUCTION) = MAIN_CONSTRAINT
    // CONSTRAINTS

    std::stringstream branch;
    branch << "br_" << std::setw(8) << std::hex << std::setfill('0') << addr << "_" << branchID;
    branch << ": " << instr;

    UINT8 val;
    PIN_GetContextRegval(ctxt, REG_RFLAGS, (UINT8*)&val);
    std::stringstream stream;
    std::bitset<16> x(val);
    stream << x;
    branch << " (" << stream.str() << ")";
    branch << " - " << getRegID(REG_RFLAGS) << std::endl;      

    // if(instr.compare(0, 3, string("jnz")) == 0) {
    //   branch << " - " << getRegID(REG_RFLAGS) << "_JNZ" << std::endl;      
    // } else if(instr.compare(0, 2, string("jz")) == 0) {
    //   branch << " - " << getRegID(REG_RFLAGS) << "_JZ" << std::endl;      
    // } else {
    //   std::cerr << "Unknown Jump: " << instr.substr(0, instr.find(" ")) << std::endl;
    // }

    //branch << getConstraints() << std::endl;
    branchData.push_back(branch.str());
  }
}

void instrument(INS instruction, void* v) {
  INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)trackInstruction,
		 IARG_ADDRINT, INS_Address(instruction),
		 IARG_PTR, new std::string(INS_Disassemble(instruction)),
		 IARG_END);
  
  if(INS_IsNop(instruction)) {
    // NOP
  } else if(INS_IsBranchOrCall(instruction)) {
    if(INS_Category(instruction) == XED_CATEGORY_COND_BR) {
      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)trackJump,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),
		     IARG_END);
    } else {
      // Direct Jumps
    }
  } else if(INS_OperandCount(instruction) > 1) {
    if(INS_IsPredicated(instruction)) {
      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)trackPredicate,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),
		     IARG_END);
    }

    if(INS_MemoryOperandIsRead(instruction, 0) && INS_OperandIsReg(instruction, 0)) {
      // MEM -> REG
      INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintMemToReg,
			       IARG_CONTEXT,
			       IARG_ADDRINT, INS_Address(instruction),
			       IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
			       IARG_MEMORYOP_EA, 0,
			       IARG_UINT32, INS_OperandReg(instruction, 0),
			       IARG_UINT32, INS_MemoryReadSize(instruction),
		     IARG_END);
      // TODO: Advance Dest Register ID
    } else if(INS_MemoryOperandIsWritten(instruction, 0)) {
      // REG -> MEM
      INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintRegToMem,
			       IARG_CONTEXT,
			       IARG_ADDRINT, INS_Address(instruction),
			       IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
			       IARG_UINT32, INS_OperandReg(instruction, 0),
			       IARG_MEMORYOP_EA, 0,
			       IARG_UINT32, INS_MemoryWriteSize(instruction),
		     IARG_END);
    } else if(INS_OperandIsReg(instruction, 0) && INS_OperandCount(instruction) > 2 && INS_RegR(instruction, 0) && INS_RegR(instruction, 1) && INS_RegW(instruction, 0)) {
      // REG -> REG
      INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintReg2ToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_UINT32, INS_RegR(instruction, 0),
		     IARG_UINT32, INS_RegR(instruction, 1),
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);
      // TODO: Advance Dest Register ID
    } else if(INS_OperandIsReg(instruction, 0) && INS_RegR(instruction, 0) && INS_RegW(instruction, 0) && INS_OperandIsImmediate(instruction, 1)) {
      // REG + CONSTANT -> REG
      INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintRegConstantToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_UINT32, INS_RegR(instruction, 0),
		     IARG_ADDRINT, INS_OperandImmediate(instruction, 1),
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);
      // TODO: Advance Dest Register ID
    } else if(INS_OperandIsReg(instruction, 0) && INS_RegR(instruction, 0) && INS_RegW(instruction, 0)) {
      // REG -> REG
      INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintRegToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_UINT32, INS_RegR(instruction, 0),
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);
      // TODO: Advance Dest Register ID
    } else if(INS_OperandIsReg(instruction, 0)) {
      // Constant -> REG
      INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintConstantToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);
    } else if(INS_MemoryOperandIsRead(instruction, 0)) {
      // MEM -> REG
      INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintMemToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_MEMORYOP_EA, 0,
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);

    } 
  }
}

bool openingTaintedFile = false;
UINT64 taintedFD;
UINT64 taintedOffset;

void enterSyscall(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD sys, void* v) {
  ADDRINT snum = PIN_GetSyscallNumber(ctxt, sys);

  /*
  std::cout << "Syscall: " << SyscallName(snum) << "("
	    << PIN_GetSyscallArgument(ctxt, sys, 0) << ", "
	    << PIN_GetSyscallArgument(ctxt, sys, 1) << ", "
	    << PIN_GetSyscallArgument(ctxt, sys, 2) << ")" << std::endl;
  */

  if(snum == __NR_open) {
    std::string fn(reinterpret_cast<const char*>(PIN_GetSyscallArgument(ctxt, sys, 0)));
    if(TaintedInput.Value().find(fn) != string::npos) {
      openingTaintedFile = true;
    }
  } else if(snum == __NR_close) {
    UINT64 fd = static_cast<UINT64>(PIN_GetSyscallArgument(ctxt, sys, 0));
    if(fd == taintedFD) {
      taintedFD = 0;
      taintedOffset = 0;
    }
  } else if(snum == __NR_read) {
    UINT64 fd = static_cast<UINT64>(PIN_GetSyscallArgument(ctxt, sys, 0));
    UINT64 addr = static_cast<UINT64>(PIN_GetSyscallArgument(ctxt, sys, 1));
    UINT64 size = static_cast<UINT64>(PIN_GetSyscallArgument(ctxt, sys, 2));
    if(fd == taintedFD) {
      UINT64 i;
      for(i = 0; i < size; i++) {
	addExternalTaint(addr + i, taintedOffset);
	taintedOffset += 1;
      }
    }
  }
}

void exitSyscall(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD sys, void* v) {
  if(openingTaintedFile) {
    taintedFD = PIN_GetSyscallReturn(ctxt, sys);
    openingTaintedFile = false;
  }
}

void finalize(INT32 ret, void* v) {
  ofstream file;
  file.open("execution.dat");
  for(list<string>::iterator i = branchData.begin(); i != branchData.end(); i++) {
    file << *i << std::endl;
  }
  file << getConstraints() << std::endl;
  // TODO: Print Path Information
  // TODO: Print Path Constraints
  if(crashed) {
    file << "SEGFAULT" << std::endl;
  }
  file.close();
}
