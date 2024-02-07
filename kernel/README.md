# FPVM w/ Kernel Module

Current working dev environment:
- Ubuntu 16.04 (4.15 kernel)
- No KPTI 
- Just use http://pdinda.org/Stuff/fpvm-vmware-vm-passwd-is-fpvm.zip


### Build and insert kernel module:
```
sudo ./kmod_setup.sh
```

### Build and run fpvm w/ test binaries:
```
cd fpvm2/ 
make clean
make menuconfig
make
./test.sh <test_name>
```

### Some current TODOs:
- enzo not working
- need to fix the nasty user_fpvm_entry
