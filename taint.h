#include <sys/types.h>

void addRegisterTaint(REG);
void removeRegisterTaint(REG);
void addMemoryTaint(UINT64);
void removeMemoryTaint(UINT64);
bool isRegisterTainted(REG);
bool isMemoryTainted(UINT64);
std::string printTaint();
void taintMemToReg(UINT64, std::string, UINT64, REG);
void taintRegToMem(UINT64, std::string, REG, UINT64);
void taintRegToReg(UINT64, std::string, REG, REG);
void taintReg2ToReg(UINT64, std::string, REG, REG, REG);
