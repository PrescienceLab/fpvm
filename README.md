# The Floating Point Virtual Machine

Copyright (c) 2021-2025 Peter Dinda and the Prescience Lab. Please see LICENSE file.
This is a tool for floating point virtualization developed as part of the [Buoyancy Project](https://buoyancy-project.org/).

For more information, see the following papers:

- P. Dinda, N. Wanninger, J. Ma, A. Bernat, C. Bernat, S. Ghosh, C. Kraemer, Y. Elmasry, *FPVM: Towards a Floating Point Virtual Machine*, Proceedings of the 31st ACM Symposium on High-performance Parallel and Distributed Computing (HDPC 2022). June, 2022. [pdf](http://pdinda.org/Papers/hpdc22.pdf)

- N. Wanninger, N. Dhiantravan, P. Dinda, *Virtualization So Light, It Floats! Accelerating Floating Point Virtualization*, Proceedings of the 34th ACM Symposium on High-performance Parallel and Distributed Computing (HDPC 2025). July, 2025. [pdf](http://pdinda.org/Papers/hpdc25.pdf)


---

## Configuring, Building and Testing

First, we require you source the `ENV.ARCH` file to build.
This will configure paths and whatnot to work with FPVM more efficiently.
You can either run `source ENV.ARCH` in your bash shell, or use [direnv](https://direnv.net/) to make your life simpler.
FPVM started with a focus on the 64 bit x86 architecture ("x64"), but now also has some support for 64 bit ARM architecture and for a variant of the 64 bit RISC-V architecture that we have developed.  The following is primarily geared to x64.

While FPVM doesn't depend on many packages, you must make sure you have them installed first.

We've tested on Ubuntu 22.04 systems with the following packages:
```bash
sudo apt install build-essential libcapstone-dev libmpfr-dev libhdf5-dev python3 python3-pip git
```

Then, make sure you have the required python packages installed:
```bash
pip3 install --user -r requirements.txt
```


To get started, you must configure FPVM using `menuconfig`.
```bash
make menuconfig
```

or, the default config can be chosen using
```bash
make defconfig
```

Then, you can build FPVM with
```bash
make -j $(nproc)
```

This will produce a `build/` folder with the results of FPVM.

Note that you can configure FPVM in "HAVE_MAIN" mode, which
creates a greatly simplified single executable that is only
useful for those doing FPVM development.

## Running FPVM

To run FPVM against a binary, you can use the `fpvm` tool to run your program.
This program is located in `scripts/`, but you should make sure to source the `ENV.ARCH` file before using it.
`ENV.ARCH` will add `scripts/` to your path.
```bash
fpvm run ./a.out
```

This will, most likely, take quite a while on the first run.
**NOTE:** FPVM will run the program once in a profiling step, so expect the program to execute at least once before running with FPVM.
This is due to the need to patch non-virtualizable parts of the binary.
Subsequent runs of the same (hash-identical) binary will be much faster, as the results are stored in `~/.cache/fpvm/`.

**NOTE:** It's important that you always run `FPVM` through the above tool.
Using FPVM.so directly will likely result in incorrect output due to wrapped functions and whatnot.


--- 

# Misc Information

## Forcing SSE at Compilation Time

To compile SSE only:
```bash
gcc ..... -mno-avx -mno-avx2 -mno-avx512f -mno-avx512pf -mno-avx512er -mno-avx512cd
```

To force libc to use SSE only:

export GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX2_Usable,-AVX_Usable,-AVX512_Usable

## Configuration

The following environment variables configure FPVM:

```
FPVM_AGGRESSIVE=y|n
    Aggressive interposition (you almost always want this)

FPVM_KERNEL=y|n
    Use kernel support if it is available (FPVM kernel module)

FPVM_DISABLE_PTHREADS=y|n
    Turn off pthread support (do not attempt to interpose on pthreads)
    You will want to set this if there is a link failure involving pthreads
    
FPVM_EXCEPT_LIST=inv;den;div;over;under;prec
    Exceptions that will invoke FPVM
    You almost certainly do not want to set this variable so that
    it can configure given the defaults

FPVM_FORCE_ROUNDING=pos|neg|zer|nea;daz;ftz
    Force rounding mode and subnormal handling on the hardware
    You almost certainly do not want to set this variable
```
