#!/bin/bash

if [ -z "${FPVM_HOME}" ]; then
	echo "Set FPVM_HOME";
	exit -1
fi	

if [ ! -e $FPVM_HOME/build/fpvm.so  ] ; then
	echo "$FPVM_HOME/build/fpvm.so does not exist - build first!"
	exit -1
fi

LD_PRELOAD=$FPVM_HOME/build/fpvm.so FPVM_AGGRESSIVE=y $@

