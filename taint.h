#include <sys/types.h>

void addRegisterTaint(REG);
void removeRegisterTaint(REG);
void addMemoryTaint(UINT64);
void removeMemoryTaint(UINT64);
bool isRegisterTainted(REG);
bool isMemoryTainted(UINT64);
std::string printTaint();
std::string getConstraints();
std::string getRegID(REG);
std::string getMemID(UINT64);
void addExternalTaint(UINT64, UINT64);
void taintMemToReg(CONTEXT*, UINT64, std::string, UINT64, REG);
void taintRegToMem(CONTEXT*, UINT64, std::string, REG, UINT64);
void taintRegToReg(CONTEXT*, UINT64, std::string, REG, REG);
void taintRegConstantToReg(CONTEXT*, UINT64, std::string, REG, ADDRINT, REG);
void taintConstantToReg(CONTEXT*, UINT64, std::string, REG);
void taintReg2ToReg(CONTEXT*, UINT64, std::string, REG, REG, REG);
