CC = gcc -lm -O3 -fno-pic -no-pie

EXEC = lbm

all: $(EXEC) $(EXEC).patched_trap $(EXEC).patched_magic

test: run run_fpvm_trap run_fpvm_magic

run: $(EXEC)
	fpvm_time.sh ./$(EXEC) 10 test.orig.out 0 0 > $(EXEC).out 2>&1

run_fpvm_trap: $(EXEC).patched_trap
	fpvm_run.sh ./$(EXEC).patched_trap 10 test.trap.out 0 0 > $(EXEC).patched_trap.out 2>&1

run_fpvm_magic: $(EXEC).patched_magic
	fpvm_run.sh ./$(EXEC).patched_magic 10 test.magic.out 0 0 > $(EXEC).patched_magic.out 2>&1

$(EXEC): $(EXEC).c main.c
	$(CC) $(EXEC).c main.c -lm -o $(EXEC)

$(EXEC).patched_trap $(EXEC).patched_magic : $(EXEC)
	fpvm_patch.sh -w workspace -m $(EXEC)

diff:
	diff $(EXEC).out $(EXEC).patched_trap.out

clean:
	rm -f $(EXEC) $(EXEC).patched_magic $(EXEC).patched_trap $(EXEC).out $(EXEC).patched_trap.out $(EXEC).patched_magic.out $(EXEC)*.timing $(EXEC)*fpvm_magic*  $(EXEC)*.csv $(EXEC).original




