
FORCE_SIG_FAULT=0x$(./ksymlookup force_sig_fault)
echo "force_sig_fault=$FORCE_SIG_FAULT"
UPROBE_GET_TRAP_ADDR=0x$(./ksymlookup uprobe_get_trap_addr)
echo "uprobe_get_trap_addr=$UPROBE_GET_TRAP_ADDR"

sudo insmod ./fptrapall/fptrapall.ko \
    force_sig_fault=$FORCE_SIG_FAULT \
    uprobe_get_trap_addr=$UPROBE_GET_TRAP_ADDR \

sudo chown $USER /sys/kernel/fptrapall/register
sudo chown $USER /sys/kernel/fptrapall/ts
sudo chown $USER /sys/kernel/fptrapall/in_signal

