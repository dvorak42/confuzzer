#include <asm/unistd.h>
#include <iomanip>
#include <iostream>
#include <fstream>
#include "pin.H"

#include "stringifier.h"
#include "taint.h"

KNOB<std::string> TaintedInput(KNOB_MODE_WRITEONCE, "pintool", "tainted-input", "NONE", "Tainted Inputs");

void instrument(INS, void*);
void enterSyscall(THREADID, CONTEXT*, SYSCALL_STANDARD, void*);
void exitSyscall(THREADID, CONTEXT*, SYSCALL_STANDARD, void*);
void finalize(INT32, void*);

int main(int argc, char* argv[]) {
  if(PIN_Init(argc, argv)) {
    std::cout << "Invalid arguments for " << argv[0] << std::endl;
    return -1;
  }

  std::cerr << "Starting Execution" << std::endl;

  StringifierSetup();

  PIN_SetSyntaxIntel();
  PIN_InitSymbols();

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
}

void trackJump(UINT64 addr, std::string instr) {
  if(isRegisterTainted(REG_RFLAGS) || isRegisterTainted(REG_EFLAGS) || isRegisterTainted(REG_FLAGS)) {
    std::cout << "Tainted Jump: " << std::hex << addr << " - " << instr << " (" << getRegID(REG_RFLAGS) << ")" <<std::endl;
    std::cout << printTaint() << std::endl;
    // TODO: Store Path Information
    // TODO: Store Path Constraint
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
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),
		     IARG_END);
    } else {
      // Direct Jumps
    }
  } else if(INS_OperandCount(instruction) > 1) {
    if(INS_MemoryOperandIsRead(instruction, 0) && INS_OperandIsReg(instruction, 0)) {
      // MEM -> REG
      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintMemToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_MEMORYOP_EA, 0,
		     IARG_UINT32, INS_OperandReg(instruction, 0),
		     IARG_END);
      // TODO: Advance Dest Register ID
    } else if(INS_MemoryOperandIsWritten(instruction, 0)) {
      // REG -> MEM

      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintRegToMem,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_UINT32, INS_OperandReg(instruction, 0),
		     IARG_MEMORYOP_EA, 0,
		     IARG_END);
    } else if(INS_OperandIsReg(instruction, 0) && INS_OperandCount(instruction) > 2 && INS_RegR(instruction, 0) && INS_RegR(instruction, 1) && INS_RegW(instruction, 0)) {
      // REG -> REG
      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintReg2ToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_UINT32, INS_RegR(instruction, 0),
		     IARG_UINT32, INS_RegR(instruction, 1),
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);
      // TODO: Advance Dest Register ID
    } else if(INS_OperandIsReg(instruction, 0) && INS_RegR(instruction, 0) && INS_RegW(instruction, 0)) {
      // REG -> REG
      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintRegToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_UINT32, INS_RegR(instruction, 0),
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);
      // TODO: Advance Dest Register ID
    } else if(INS_OperandIsReg(instruction, 0)) {
      // Constant -> REG
      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintConstantToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);
    } else if(INS_MemoryOperandIsRead(instruction, 0)) {
      // MEM -> REG
      INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)taintMemToReg,
		     IARG_CONTEXT,
		     IARG_ADDRINT, INS_Address(instruction),
		     IARG_PTR, new std::string(INS_Disassemble(instruction)),		     
		     IARG_MEMORYOP_EA, 0,
		     IARG_UINT32, INS_RegW(instruction, 0),
		     IARG_END);

    } 
  }
}

static bool openingTaintedFile = false;
static UINT64 taintedFD;

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
    }
  } else if(snum == __NR_read) {
    UINT64 fd = static_cast<UINT64>(PIN_GetSyscallArgument(ctxt, sys, 0));
    UINT64 addr = static_cast<UINT64>(PIN_GetSyscallArgument(ctxt, sys, 1));
    UINT64 size = static_cast<UINT64>(PIN_GetSyscallArgument(ctxt, sys, 2));
    if(fd == taintedFD) {
      UINT64 i;
      for(i = 0; i < size; i++) {
	addMemoryTaint(addr + i);
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
  // TODO: Print Path Information
  // TODO: Print Path Constraints
  file.close();
}
