all: play play.patched fpvm_magic

play: play.c
	gcc -O2 -fno-pic -no-pie play.c -o play
	objdump -d play > play.dis


play.patched : play fpvm_magic
	echo Ask Nick to run analysis and patching
	echo or wait for the docker-script here
	echo either way, keep the csv files
	echo play_call_patches.csv and play_mem_patches.csv
	e9tool -M "addr=play_call_patches[0]" -P "before fpvm_correctness_trap()@fpvm_magic" -M "addr=play_mem_patches[0]" -P "fpvm_correctness_trap()@fpvm_magic" play
	mv a.out play.patched


fpvm_magic: fpvm_magic.c
	e9compile.sh fpvm_magic.c

clean:
	rm -f play play.patched fpvm_magic.o fpvm_magic

