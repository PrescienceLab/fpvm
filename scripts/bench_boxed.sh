#!/bin/bash

BASE_OPTIONS=(
  "#define CONFIG_NO_OUTPUT 0"
  "#define CONFIG_DEBUG 0"
  "#define CONFIG_DEBUG_ALT_ARITH 0"
  
  "#define CONFIG_TELEMETRY 0"
  "#define CONFIG_TELEMETRY_PROMOTIONS 0"
  "#define CONFIG_TELEMETRY_PERIOD 0"

  "#define CONFIG_PERF_STATS 0"
  "#define CONFIG_PERF_STATS_PERIOD 0"

  "#define CONFIG_INSTR_TRACES 0"
  "#define CONFIG_INSTR_TRACES_PERIOD 0"

  "#define CONFIG_TRAP_SHORT_CIRCUITING 0"
  "#define CONFIG_INSTR_SEQ_EMULATION 0"
  "#define CONFIG_MAGIC_CORRECTNESS_TRAP 0"
  "#define CONFIG_KERNEL_SHORT_CIRCUITING 0"

  "#define CONFIG_ALT_MATH_VANILLA 0"
  "#define CONFIG_ALT_MATH_BOXED_IEEE 1"
  "#define CONFIG_ALT_MATH_POSIT 0"
  "#define CONFIG_ALT_MATH_MPFR 0"
  "#define CONFIG_ALT_MATH_RATIONAL 0"
)

if [[ -z "${FPVM_HOME}" ]]; then
  echo "Please source ENV at the root of the FPVM dir"
  exit -1
fi

if [[ "$#" -ne 2 ]]; then
  echo "Usage: bench_boxed.sh <TEST_DIR> <TEST_NAME>"
  echo "TEST_NAME should be the name of the benchmark/binary (e.g. lorenz_attractor)"
  exit -1
fi

CONFIG_FILE=$FPVM_HOME/include/fpvm/config.h
TEST_DIR=$1
TEST_NAME=$2

OUTPUT_DIR=$FPVM_HOME/bench_data/boxed/$TEST_NAME
OUTPUT_BACKUP_DIR=${OUTPUT_DIR}_old

rm -rf $OUTPUT_BACKUP_DIR
mv $OUTPUT_DIR $OUTPUT_BACKUP_DIR
mkdir -p $OUTPUT_DIR

function clear_config() {
  printf "%s\n" "${BASE_OPTIONS[@]}" > $CONFIG_FILE

  printf '\033[0;32m'
  echo "Config reset to base"
  printf '\033[0m'
}

function set_option() {
  if [[ $# -ne 1 ]]; then
    echo "ERROR: set_option() called without config argument"
    exit -1
  fi
  if grep -q "$1" $CONFIG_FILE; then
    sed -i "/$1/s/0/1/g" $CONFIG_FILE
    printf '\033[0;32m'
    grep "$1" $CONFIG_FILE
    printf '\033[0m'
  else 
    echo "ERROR: Invalid config option passed to set_option()"
    exit -1
  fi
}

function unset_option() {
  if [[ $# -ne 1 ]]; then
    echo "ERROR: unset_option() called without config argument"
    exit -1
  fi
  if grep -F -q "$1" $CONFIG_FILE; then
    sed -i "/$1/s/1/0/g" $CONFIG_FILE
    printf '\033[0;32m'
    grep -F "$1" $CONFIG_FILE
    printf '\033[0m'
  else 
    echo "ERROR: Invalid config option passed to set_option()"
    exit -1
  fi
}

function init_test() {
  pushd $TEST_DIR
  make clean
  make
  popd
}

function run_test() {
  pushd $TEST_DIR
  make test
  popd
}

function log_diffs() {
  if [[ $# -ne 1 ]]; then
    echo "ERROR: log_diffs() called without name argument"
    exit -1
  fi
  echo "======" >> ${OUTPUT_DIR}/trap_diff.out
  echo "======" >> ${OUTPUT_DIR}/magic_diff.out
  echo $1 >> ${OUTPUT_DIR}/trap_diff.out
  echo $1 >> ${OUTPUT_DIR}/magic_diff.out
  diff <(grep -v "fpvm time" ${TEST_DIR}/${TEST_NAME}.out) <(grep -v "fpvm time" ${TEST_DIR}/${TEST_NAME}.patched_trap.out) >> ${OUTPUT_DIR}/trap_diff.out 
  diff <(grep -v "fpvm time" ${TEST_DIR}/${TEST_NAME}.out) <(grep -v "fpvm time" ${TEST_DIR}/${TEST_NAME}.patched_magic.out) >> ${OUTPUT_DIR}/magic_diff.out
}

# We'll have to do this specially I think
HW2KERN=200
KERN2USER=400
CALLWRAP=100
BASELINE=${TEST_NAME}.out


function gen_graph_data() {
  pushd ${TEST_DIR}
  generate_graph_inputs.pl $1 $2 $HW2KERN $KERN2USER $CALLWRAP $BASELINE $3
  popd
}

# NOTE: This function expects to be called with all configs set to 0
# except for "NO_OUTPUT", the factors, and the alt math choice
function do_all_graph_data() {
  if [[ $# -ne 3 ]]; then
    echo "ERROR: do_all_graph_data() improper usage"
    exit -1
  fi

  bench=$1
  factors=$2
  outfile=$3

  # Basic Timing
  gen_graph_data $bench $factors $outfile
  mv ${TEST_DIR}/${bench}.${factors}.timing.txt $OUTPUT_DIR
  # Amortcount (Telem)
  unset_option "NO_OUTPUT"
  set_option "TELEMETRY "
  set_option "TELEMETRY_PROMOTIONS"
  make
  run_test
  gen_graph_data $bench $factors $outfile
  mv ${TEST_DIR}/${bench}.${factors}.amortcount.txt $OUTPUT_DIR
  # Amortcost (Telem + Perf)
  set_option "PERF_STATS "
  make
  run_test
  gen_graph_data $bench $factors $outfile
  mv ${TEST_DIR}/${bench}.${factors}.amortcost.txt $OUTPUT_DIR
  # TraceHist/Rank (Telem + Perf + Trace)
  set_option "TRACES "
  make
  run_test
  gen_graph_data $bench $factors $outfile
  mv ${TEST_DIR}/${bench}.${factors}.tracehist.txt $OUTPUT_DIR
  mv ${TEST_DIR}/${bench}.${factors}.tracerank.txt $OUTPUT_DIR


}

init_test

### Test base (nothing turned on)
## Correctness
clear_config
set_option "NO_OUTPUT"
make
run_test
log_diffs "none"
## Graph Data
bench=${TEST_NAME}
factors="none"
outfile="${TEST_NAME}.patched_trap.out"
do_all_graph_data $bench $factors $outfile

### SEQ
## Correctness
clear_config
set_option "NO_OUTPUT"
set_option "INSTR_SEQ_EMULATION"
make
run_test
log_diffs "seq"
## Graph Data
bench=${TEST_NAME}
factors="seq"
outfile="${TEST_NAME}.patched_trap.out"
do_all_graph_data $bench $factors $outfile


### MAGIC
## Correctness
clear_config
set_option "NO_OUTPUT"
set_option "MAGIC"
make
run_test
log_diffs "magic"
## Graph Data
bench=${TEST_NAME}
factors="magic"
outfile="${TEST_NAME}.patched_magic.out"
do_all_graph_data $bench $factors $outfile

### SEQ + MAGIC
## Correctness
clear_config
set_option "NO_OUTPUT"
set_option "INSTR_SEQ_EMULATION"
set_option "MAGIC"
make
run_test
log_diffs "seq-magic"
## Graph Data
bench=${TEST_NAME}
factors="seq-magic"
outfile="${TEST_NAME}.patched_magic.out"
do_all_graph_data $bench $factors $outfile



# LOAD KMOD

# TODO: KMOD

# TODO: SEQ + KMOD

# TODO: KMOD + MAGIC

# TODO: SEQ + KMOD + MAGIC
