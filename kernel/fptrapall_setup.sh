#! /usr/bin/bash

if ! lsmod | grep -q "fptrapall"; then

    FORCE_SIG_FAULT=0x$(./ksymlookup force_sig_fault)
    echo "force_sig_fault=$FORCE_SIG_FAULT"
    UPROBE_GET_TRAP_ADDR=0x$(./ksymlookup uprobe_get_trap_addr)
    echo "uprobe_get_trap_addr=$UPROBE_GET_TRAP_ADDR"

    sudo insmod ./fptrapall/fptrapall.ko \
        force_sig_fault=$FORCE_SIG_FAULT \
        uprobe_get_trap_addr=$UPROBE_GET_TRAP_ADDR
fi

sudo chown -R root /sys/kernel/fptrapall
sudo chgrp -R authors /sys/kernel/fptrapall
sudo chmod -R 770 /sys/kernel/fptrapall

