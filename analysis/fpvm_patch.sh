#!/usr/bin/env bash

PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")


OLD_DIR=$PWD
BIN=$(realpath $1)

pushd ${PFX}

  if [ ! -d e9patch ]; then
    git clone https://github.com/GJDuck/e9patch.git
    cd e9patch && ./build.sh
  fi
  export PATH=$PFX/e9patch:$PATH


  # Delete the old workspace folder
  rm -rf workspace
  # Make a new one
  mkdir -p workspace
  # Copy the binary into the right location
  cp $BIN workspace/input
  # Copy other stuff we will want
  cp /usr/bin/time workspace
  # Run the patch
  docker buildx build --progress=plain -o workspace/ .


  pushd workspace

  
    # Patch with traps
    e9tool -M 'addr=call_patches[0]' -P 'before trap' \
            -M 'addr=mem_patches[0]' -P 'before trap' \
            input --output input.patched_trap
    cp input.patched_trap ${BIN}.patched_trap

    # Build magic
    e9compile.sh ../magictrap/fpvm_magic.c

    # Patch with magic
    e9tool -M "addr=call_patches[0]" -P "before fpvm_correctness_trap<naked>()@fpvm_magic" \
           -M "addr=mem_patches[0]" -P "fpvm_correctness_trap<naked>()@fpvm_magic" \
           input --output input.patched_magic

    cp input.patched_magic ${BIN}.patched_magic
    
    # copy out working files for sanity
    cp call_patches.csv ${BIN}.call_patches.csv
    cp mem_patches.csv ${BIN}.mem_patches.csv
    cp fpvm_magic ${BIN}.fpvm_magic
    cp ../magictrap/fpvm_magic.c ${BIN}.fpvm_magic.c
    cp input ${BIN}.original
    cp generate.profile ${BIN}.generate.profile
    cp taintsource.profile ${BIN}.taintsource.profile
    cp taintsink.profile ${BIN}.taintsink.profile
    cp generate.timing ${BIN}.generate.timing
    cp taintsource.timing ${BIN}.taintsource.timing
    cp taintsink.timing ${BIN}.taintsink.timing


    
  popd
popd
