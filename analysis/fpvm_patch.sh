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
  # Run the patch
  docker buildx build --progress=plain -o workspace/ .


  pushd workspace

    # Patch with traps
    e9tool -M 'addr=call_patches[0]' -P 'before trap' \
            -M 'addr=mem_patches[0]' -P 'before trap' \
            input --output input.patched_trap
    cp input.patched_trap ${BIN}.patched_trap


    e9compile.sh ../magictrap/fpvm_magic.c

    e9tool -M "addr=call_patches[0]" -P "before fpvm_correctness_trap()@fpvm_magic" \
           -M "addr=mem_patches[0]" -P "fpvm_correctness_trap()@fpvm_magic" \
           input --output input.patched_magic

    cp input.patched_magic ${BIN}.patched_magic
    

  popd
popd
