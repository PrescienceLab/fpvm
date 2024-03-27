#!/usr/bin/env bash
set  -xe
if [[ -z "${FPVM_HOME}" ]] ; then
    echo "Please set FPVM_HOME"
    exit 1;
fi

if [[ -z "${FPVM_WRAP}" ]] ; then
    echo "Please set FPVM_WRAP"
    exit 1;
fi



PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")


OLD_DIR=$PWD


# Parse the command line arguments
BIN=""
workspace="${PFX}/workspace/"
memonly="no"
copyout="yes"

# Parse command-line arguments
while getopts "nw:m?" opt; do
  case ${opt} in
    w )
      workspace=$(realpath "$OPTARG")
      ;;
    m )
      memonly="yes"
      ;;
    n )
      copyout="no"
      ;;
    \? )
      echo "Usage: $(basename $0) [-w WORKSPACE] [-m] <binary>"
      echo "  -w WORKSPACE : use WORKSPACE as workspace"
      echo "                 instead of default shared workspace"
      echo "  -m           : do memory patching only"
      echo "                 for example to use wrapper method"
      echo "  -n           : do not copy out intermediary files"
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

BIN=$(realpath $1)


echo $BIN
echo $workspace

[[ -z "${BIN}" ]] && { echo "No binary provided" ; fpvm_patch.sh -? ; exit 1; }



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

  docker build -t fpvm_patch .
  docker run --rm --mount type=bind,source=${workspace},target=/root/output fpvm_patch
  # Run the patch, copying the results to the workspace folder
  # docker buildx build --progress=plain -o $workspace .


  pushd $workspace

  # do forward wrapping if necessary
  if [[ "${FPVM_WRAP}" == "reverse" ]] ; then
      cp input input.prewrapped
      echo "Modifying binary to support reverse wrappers"
      fpvm_wrap -o input.wrapped -f ${FPVM_HOME}/wrap.list input.prewrapped
      if [ $? -ne 0 ]; then
	  echo "Failed to modify binary to support reverse wrappers"
	  exit -1;
      fi
      cp input.wrapped input
      echo "Replaced temporary executable with wrapped version"
  fi
  
  
  # Build magic
  echo "Building magic"
  cp ${FPVM_HOME}/analysis/magictrap/fpvm_magic.[ch] .
  e9compile.sh fpvm_magic.c

  echo "Patching executable"
  # patch the executable
  if [ "${memonly}" = "no" ]; then
      # patch mem and call insts with traps
      e9tool -M 'addr=call_patches[0]' -P 'before trap' \
             -M 'addr=mem_patches[0]' -P 'before trap' \
             input --output input.patched_trap
      # patch mem and call insts with magic
      e9tool -M "addr=call_patches[0]" -P "before fpvm_correctness_trap<naked>()@fpvm_magic" \
             -M "addr=mem_patches[0]" -P "fpvm_correctness_trap<naked>()@fpvm_magic" \
             input --output input.patched_magic
  else
      # patch meminsts with traps
      e9tool -M 'addr=mem_patches[0]' -P 'before trap' \
             input --output input.patched_trap
      # patch mem insts with magic
      e9tool -M "addr=mem_patches[0]" -P "fpvm_correctness_trap<naked>()@fpvm_magic" \
             input --output input.patched_magic
  fi
  
  #
  # Generate function info
  #
  if [ "${copyout}" = "yes" ]; then
    patches_to_functions.pl mem_patches.csv input > input.mem_patch.info
    patches_to_functions.pl call_patches.csv input > input.call_patch.info
    
    # copy out working files for sanity
    cp input.patched_trap ${BIN}.patched_trap
    cp input.patched_magic ${BIN}.patched_magic
    cp call_patches.csv ${BIN}.call_patches.csv
    cp mem_patches.csv ${BIN}.mem_patches.csv
    cp input.mem_patch.info ${BIN}.mem_patch.info
    cp input.call_patch.info ${BIN}.call_patch.info
    cp fpvm_magic ${BIN}.fpvm_magic
    cp fpvm_magic.c ${BIN}.fpvm_magic.c
    cp fpvm_magic.h ${BIN}.fpvm_magic.h
    cp input ${BIN}.original
    # cp generate.profile ${BIN}.generate.profile
    # cp taintsource.profile ${BIN}.taintsource.profile
    # cp taintsink.profile ${BIN}.taintsink.profile
    cp generate.timing ${BIN}.generate.timing
    cp taintsource.timing ${BIN}.taintsource.timing
    cp taintsink.timing ${BIN}.taintsink.timing
    cp analysis.out ${BIN}.analysis.out
    if [[ "${FPVM_WRAP}" == "reverse" ]] ; then
	cp input.prewrapped ${BIN}.prewrapped
	cp input.prewrapped ${BIN}.original
	cp input.wrapped ${BIN}.wrapped
    fi
  fi
  
  if [[ "${FPVM_WRAP}" == "reverse" ]] ; then
      printf '\e[31mExecutable is reverse wrapped\e[0m\n'
  fi
  
  
  if [ "${memonly}" = "no" ]; then
      echo "Patched executables for memory and calls"
  else
      printf '\e[31m'
      echo "Patched executables for memory only"
      echo "Assuming you will handle calls in alternative manner"
      echo "If you are using wrappers, be sure to update"
      echo "your wrap.list using get_dynamic_calls.pl"
      echo "and rebuild FPVM if necessary"
      printf '\e[0m'
  fi
  popd
popd
