sudo bash -c "echo 0 > /proc/sys/kernel/yama/ptrace_scope"
sudo bash -c "echo core > /proc/sys/kernel/core_pattern"
ulimit -c unlimited