#!/bin/bash


if [ -z "$1" ] ; then
  echo "fpvm_run.sh <command>"
  exit -1
fi    

if [ -z "${FPVM_HOME}" ]; then
  echo "Using a default FPVM_HOME";
  FPVM_HOME=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/../")
fi

if [ ! -e $FPVM_HOME/build/fpvm.so  ] ; then
  echo "$FPVM_HOME/build/fpvm.so does not exist - build first!"
  exit -1
fi

export GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX2_Usable,-AVX_Usable,-AVX512_Usable

time LD_PRELOAD=$FPVM_HOME/build/fpvm.so FPVM_AGGRESSIVE=y $@

