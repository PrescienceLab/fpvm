#!/bin/bash

if [[ -z "${FPVM_HOME}" ]] ; then
    echo "Please set FPVM_HOME"
    exit 1;
fi


gdb -ix ${FPVM_HOME}/scripts/gdb-init $@


