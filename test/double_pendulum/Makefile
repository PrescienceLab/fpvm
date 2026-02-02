# PREFIX allows you to use a cross-compiler to build fbench. For example,
# make PREFIX='riscv64-unknown-linux-gnu-' will cross-compile for RISC-V.
PREFIX =
CXX = $(PREFIX)g++
CFLAGS = -g -O3 -fno-pic -no-pie

EXEC = double_pendulum

all: $(EXEC)

$(EXEC): $(EXEC).cpp
	$(CXX) $(CFLAGS) $(EXEC).cpp -lm -o $(EXEC)


diff:
	diff $(EXEC).out $(EXEC).patched_trap.out


clean:
	rm -f $(EXEC) $(EXEC).patched_magic $(EXEC).patched_trap $(EXEC).out $(EXEC).patched_trap.out $(EXEC).patched_magic.out $(EXEC)*.timing $(EXEC)*fpvm_magic*  $(EXEC)*.csv $(EXEC).original
