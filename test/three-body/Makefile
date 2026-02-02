# PREFIX allows you to use a cross-compiler to build fbench. For example,
# make PREFIX='riscv64-unknown-linux-gnu-' will cross-compile for RISC-V.
PREFIX =
CXX = $(PREFIX)gcc
CFLAGS = -O2 -fno-pic -no-pie

EXEC = three_body_simulation
all: $(EXEC)

$(EXEC): $(EXEC).c rkf45.c
	$(CXX) $(CFLAGS) $(EXEC).c rkf45.c -lm -o $(EXEC)

clean:
	rm -f $(EXEC) $(EXEC).patched_magic $(EXEC).patched_trap $(EXEC).out $(EXEC).patched_trap.out $(EXEC).patched_magic.out $(EXEC)*.timing $(EXEC)*fpvm_magic*  $(EXEC)*.csv $(EXEC).original
