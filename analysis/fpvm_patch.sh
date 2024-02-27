#!/usr/bin/env bash

if [[ -z "${FPVM_HOME}" ]] ; then
    echo "Please set FPVM_HOME"
    exit 1;
fi


PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")


OLD_DIR=$PWD

# Parse the command line arguments
BIN=""
workspace="${PFX}/workspace/"

# Parse command-line arguments
while getopts ":w:" opt; do
  case ${opt} in
    w )
      workspace=$(realpath "$OPTARG")
      ;;
    \? )
      echo "Usage: $(basename $0) [-w WORKSPACE] <binary>"
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

BIN=$(realpath $1)


echo $BIN
echo $workspace

[[ -z "${BIN}" ]] && { echo "No binary provided" ; exit 1; }



pushd ${PFX}

  if [ ! -d e9patch ]; then
    git clone https://github.com/GJDuck/e9patch.git
    cd e9patch && ./build.sh
  fi
  export PATH=$PFX/e9patch:$PATH


  # Delete the old workspace folder
  rm -rf ${workspace}
  # Make a new one
  mkdir -p ${workspace}
  # Copy the binary into the right location
  cp $BIN ${workspace}/input
  # Copy other stuff we will want
  cp /usr/bin/time ${workspace}
  # Run the patch, copying the results to the workspace folder
  docker buildx build --progress=plain -o $workspace .


  pushd $workspace

  
    # Patch with traps
    e9tool -M 'addr=call_patches[0]' -P 'before trap' \
            -M 'addr=mem_patches[0]' -P 'before trap' \
            input --output input.patched_trap
    cp input.patched_trap ${BIN}.patched_trap

    # Build magic
    cp ${FPVM_HOME}/analysis/magictrap/fpvm_magic.c .
    e9compile.sh fpvm_magic.c

    # Patch with magic
    e9tool -M "addr=call_patches[0]" -P "before fpvm_correctness_trap<naked>()@fpvm_magic" \
           -M "addr=mem_patches[0]" -P "fpvm_correctness_trap<naked>()@fpvm_magic" \
           input --output input.patched_magic

    cp input.patched_magic ${BIN}.patched_magic
    
    # copy out working files for sanity
    cp call_patches.csv ${BIN}.call_patches.csv
    cp mem_patches.csv ${BIN}.mem_patches.csv
    cp fpvm_magic ${BIN}.fpvm_magic
    cp fpvm_magic.c ${BIN}.fpvm_magic.c
    cp input ${BIN}.original
    cp generate.profile ${BIN}.generate.profile
    cp taintsource.profile ${BIN}.taintsource.profile
    cp taintsink.profile ${BIN}.taintsink.profile
    cp generate.timing ${BIN}.generate.timing
    cp taintsource.timing ${BIN}.taintsource.timing
    cp taintsink.timing ${BIN}.taintsink.timing


    
  popd
popd
