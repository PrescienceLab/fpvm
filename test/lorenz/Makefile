CXX = g++ -O3 -fno-pic -no-pie

EXEC = lorenz_attractor

all: $(EXEC) $(EXEC).patched_trap $(EXEC).patched_magic

test: run run_fpvm_trap run_fpvm_magic

run: $(EXEC)
	fpvm_time.sh ./$(EXEC) > $(EXEC).out 2>&1

run_fpvm_trap: $(EXEC).patched_trap
	fpvm_run.sh ./$(EXEC).patched_trap > $(EXEC).patched_trap.out 2>&1


run_fpvm_magic: $(EXEC).patched_magic
	fpvm_run.sh ./$(EXEC).patched_magic > $(EXEC).patched_magic.out 2>&1

$(EXEC): $(EXEC).cpp
	$(CXX) $(EXEC).cpp -lm -o $(EXEC)

$(EXEC).patched_trap $(EXEC).patched_magic : $(EXEC)
	fpvm_patch.sh -m $(EXEC)

diff:
	diff $(EXEC).out $(EXEC).patched_trap.out


clean:
	rm -f $(EXEC) $(EXEC).patched_magic $(EXEC).patched_trap $(EXEC).out $(EXEC).patched_trap.out $(EXEC).patched_magic.out $(EXEC)*.timing $(EXEC)*fpvm_magic*  $(EXEC)*.csv $(EXEC).original




