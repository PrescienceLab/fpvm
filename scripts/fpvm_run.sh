#!/bin/bash


LD_PRELOAD=build/fpvm.so FPVM_DISABLE_PTHREADS=y FPVM_AGGRESSIVE=y $@

