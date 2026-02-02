# PREFIX allows you to use a cross-compiler to build fbench. For example,
# make PREFIX='riscv64-unknown-linux-gnu-' will cross-compile for RISC-V.
PREFIX =
CXX = $(PREFIX)gcc
CFLAGS = -lm -O3 -fno-pic -no-pie

EXEC = ffbench

all: $(EXEC)

$(EXEC): $(EXEC).c
	$(CXX) $(CFLAGS) $(EXEC).c -lm -o $(EXEC)

clean:
	rm -f $(EXEC) $(EXEC).patched_magic $(EXEC).patched_trap $(EXEC).out $(EXEC).patched_trap.out $(EXEC).patched_magic.out $(EXEC)*.timing $(EXEC)*fpvm_magic*  $(EXEC)*.csv $(EXEC).original
