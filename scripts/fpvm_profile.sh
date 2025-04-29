#!/usr/bin/bash

set -e

HERE=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/")
FPVM=$HERE/../
PROFILER=$HERE/../profiler/run


E9PATCH=$FPVM/profiler/e9patch
pushd $FPVM/ >/dev/null
  if [ ! -d $E9PATCH ]; then
     pushd $FPVM/profiler
        git clone https://github.com/GJDuck/e9patch.git
        pushd e9patch
            git reset --hard 179d9e6a727ec0ad6009b00692c2fecf9324eaff
            ./build.sh
        popd
     popd
  fi
  export PATH=$E9PATCH:$PATH
popd >/dev/null

# A little challange here is that we have to run the profiler from the directory the
# user ran it from, since they might pass an input file as an argument and we have
# to allow the application to access that. So for now, we dump all the files out
# to the current dir (making a mess) and we will copy them back out into the cache
# afterwards in scripts/fpvm.
# These are the files which should be copied:
#   profile.out
#   profile.err
#   mem_patches.csv
#   patched_magic
#   patched_trap


step() {
    NAME=$1
    shift
    "$@" 2>&1 | sed $'s|^|\x1b[34m['"${NAME}"$']\x1b[39m |' || exit 1
}


rm -f mem_patches.csv

to_patch=$(which "$1")
shift
bin=$(which "$1")
shift


# Run the profiler, which should dump mem_patches.csv into the current directory
step "profile" $PROFILER $bin $@ # > profile.out 2> profile.err

cp ${FPVM}/profiler/fpvm_magic.[ch] .

# compile the fpvm_magic.c program from the analysis
step "compile patch lib" e9compile.sh fpvm_magic.c
rm fpvm_magic.[ch]



# patch meminsts with traps
step "patch trap" e9tool -M 'addr=mem_patches[0]' -P 'before trap' \
        ${to_patch} --output patched_trap


# patch mem insts with magic
# e9tool -M "addr=mem_patches[0]" -P "fpvm_correctness_trap<naked>()@fpvm_magic" \
#         ${bin} --output patched_magic

step "patch magic" e9tool -M "addr=mem_patches[0]" -P "after fpvm_correctness_trap_test(asm,state,bytes,&dst[0])@fpvm_magic" \
        ${to_patch} --output patched_magic


rm fpvm_magic
