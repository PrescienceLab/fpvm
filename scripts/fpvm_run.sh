#!/bin/bash

if [ -z "${FPVM_HOME}" ]; then
	echo "Using a default FPVM_HOME";
  FPVM_HOME=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/../")
fi

if [ ! -e $FPVM_HOME/build/fpvm.so  ] ; then
	echo "$FPVM_HOME/build/fpvm.so does not exist - build first!"
	exit -1
fi

LD_PRELOAD=$FPVM_HOME/build/fpvm.so FPVM_AGGRESSIVE=y $@

