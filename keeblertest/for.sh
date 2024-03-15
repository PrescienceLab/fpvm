#!/usr/bin/bash

set -e
set -x
gcc -c -fPIC foobar.c
gcc -shared -o libfoobar.so foobar.o
gcc -no-pie -fno-pic foo.c -L. -lfoobar -o foo
#keeblerize.pl foo foobar
objcopy --redefine-sym foobar=foobar\$fpvm foo foo.redef && cp foo foo.orig && cp foo.redef foo
#export LD_LIBRARY_PATH=`pwd`
#./foo
#export LD_BIND_NOW=1
#fpvm_run.sh ./foo.redef
#gdb_it.sh ./foo
