CXX = g++ -O3 -fno-pic -no-pie

EXEC = lorenz_attractor

all: $(EXEC)

test: run run_fpvm_trap

run: $(EXEC)
	fpvm_time.sh ./$(EXEC) > $(EXEC).out 2>&1

$(EXEC): $(EXEC).cpp
	$(CXX) $(EXEC).cpp -lm -o $(EXEC)

diff:
	diff $(EXEC).out $(EXEC).patched_trap.out


clean:
	rm -f $(EXEC) $(EXEC).patched_magic $(EXEC).patched_trap $(EXEC).out $(EXEC).patched_trap.out $(EXEC).patched_magic.out $(EXEC)*.timing $(EXEC)*fpvm_magic*  $(EXEC)*.csv $(EXEC).original




