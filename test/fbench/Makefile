CXX = gcc -lm -O3 -fno-pic -no-pie

EXEC = fbench

all: $(EXEC)

run: $(EXEC)
	fpvm_time.sh ./$(EXEC) > $(EXEC).out 2>&1

$(EXEC): $(EXEC).c
	$(CXX) $(EXEC).c -lm -o $(EXEC)

clean:
	rm -f $(EXEC) $(EXEC).patched_magic $(EXEC).patched_trap $(EXEC).out $(EXEC).patched_trap.out $(EXEC).patched_magic.out $(EXEC)*.timing $(EXEC)*fpvm_magic*  $(EXEC)*.csv $(EXEC).original




