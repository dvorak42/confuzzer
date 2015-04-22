all: confuzzer.so test1 test2 test3 test4

CFLAGS := -std=c++0x
INCLUDE	:= $(PIN_PATH)/source/include/pin $(PIN_PATH)/source/include/pin/gen $(PIN_PATH)/extras/components/include $(PIN_PATH)/extras/xed2-intel64/include $(PIN_PATH)/source/tools/InstLib
LIBDIRS	:= $(PIN_PATH)/intel64/lib $(PIN_PATH)/intel64/lib-ext $(PIN_PATH)/intel64/runtime/glibc $(PIN_PATH)/extras/xed2-intel64/lib
LIBS    := -lpin -lxed -ldwarf -lelf -ldl -lz3
VERSION_SCRIPT := $(PIN_PATH)/source/include/pin/pintool.ver
OBJS	:= confuzzer.o taint.o stringifier.o

%.o: %.cpp
	$(CXX) -O3 -fPIC -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -Wall -Wno-unknown-pragmas -fno-stack-protector -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX  -O3 -fomit-frame-pointer -fno-strict-aliasing $(foreach d, $(INCLUDE), -I$d) $(CFLAGS) $< -c -o $@ -Wall


%.so: %.o $(OBJS)
	$(CXX) -shared -Wl,--hash-style=sysv -Wl,-Bsymbolic -Wl,--version-script=$(VERSION_SCRIPT) $(foreach d, $(LIBDIRS), -L$d) $(OBJS) -o $@ $(LIBS)

test%: test%.c
	$(CC) $< -mno-sse -mno-sse2 -static -o $@

clean:
	rm -f *.so *.o *.d pin.log test1 test2
