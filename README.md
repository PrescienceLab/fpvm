# The Floating Point Virtual Machine

Copyright (c) 2025 Prescience Lab. Please see LICENSE file.
This is a tool for floating point trap and emulate processing on x64.
This is a work in progress


---

## Configuring, Building and Testing

First, we require you source the `ENV` file to build.
This will configure paths and whatnot to work with FPVM more efficiently.
You can either run `source ENV` in your bash shell, or use [direnv](https://direnv.net/) to make your life simpler.


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

## Running FPVM

To run FPVM against a binary, you can use the `fpvm` tool to run your program:
```bash
fpvm run ./a.out
```

This will, most likely, take quite a while on the first run.
**NOTE** FPVM will run the program once in a profiling step, so expect the program to execute at least once before running with FPVM.
This is due to the need to patch non-virtualizable parts of the binary.
Subsequent runs of the same (hash-identical) binary will be much faster, as the results are stored in `~/.cache/fpvm/`.

If you wish to run the patched binary directly, you can get the exact hash identifier using the following command:
```bash
# Ask FPVM to patch lu
$ fpvm patch nas/lu
--- snip ---
/~.cache/fpvm/b63c5a2f481baaf3bed306a32edb1d6df8b43a24-patch-lu/lu.magic
# ^ output of patching (potentially already cached)
```

This will patch the binary, then print the cache location of the resultant binary.
You can then run that binary directly using:
```bash
fpvm run --nopatch ~/.cache/fpvm/b63c5a2f481baaf3bed306a32edb1d6df8b43a24-patch-lu/lu.magic
```

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
