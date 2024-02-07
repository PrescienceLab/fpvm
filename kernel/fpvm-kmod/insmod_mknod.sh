#!/bin/sh

insmod fpvm_dev.ko \
    fpvm_error_entry=0x$(grep ' error_entry' /proc/kallsyms | cut -d' ' -f1) \
    fpvm_error_return=0x$(grep ' error_exit' /proc/kallsyms | cut -d' ' -f1) \
    fpvm_pti_clone_pgtable=0x$(grep -m1 ' pti_clone_pgtable' /proc/kallsyms | cut -d' ' -f1) 
    

cd /dev
mknod fpvm_dev c 17 0
