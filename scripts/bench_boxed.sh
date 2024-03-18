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
    echo "ERROR: set_config() called without config argument"
    exit -1
  fi
  if grep -q $1 $CONFIG_FILE; then
    sed -i "/$1/s/0/1/g" $CONFIG_FILE
    printf '\033[0;32m'
    grep $1 $CONFIG_FILE
    printf '\033[0m'
  else 
    echo "ERROR: Invalid config option passed to set_option()"
    exit -1
  fi
}

function run_test() {
  pushd $TEST_DIR
  make
  make test
  popd
}

function log_diffs() {
  if [[ $# -ne 1 ]]; then
    echo "ERROR: log_diffs() called without name argument"
    exit -1
  fi
  echo $1 >> diff.out
  echo "TRAP" >> diff.out
  diff ${TEST_DIR}/${TEST_NAME}.out ${TEST_DIR}/${TEST_NAME}.patched_trap.out >> ${OUTPUT_DIR}/trap_diff.out 
  echo "MAGIC" >> diff.out
  diff ${TEST_DIR}/${TEST_NAME}.out ${TEST_DIR}/${TEST_NAME}.patched_magic.out >> ${OUTPUT_DIR}/magic_diff.out
}

function log_runtime() {
  if [[ $# -ne 1 ]]; then
    echo "ERROR: log_runtime() called without name argument"
    exit -1
  fi
  grep "real" ${TEST_DIR}/${TEST_NAME}.out >> ${1}
  grep "trap" ${TEST_DIR}/${TEST_NAME}.patched_trap.out >> ${1}_trap
  grep "magic" ${TEST_DIR}/${TEST_NAME}.patched_magic.out >> ${1}_magic
}


# Test base (nothing turned on)
clear_config
make
run_test
log_diffs "BASE"
log_runtime "BASE"

# INSTR_SEQ
clear_config
set_option "INSTR_SEQ_EMULATION" 
make
run_test
log_diffs "SEQ"
log_runtime "SEQ"

# INSTR_SEQ + MAGIC
clear_config
set_option "INSTR_SEQ_EMULATION" 
set_option "MAGIC_CORRECTNESS_TRAP"
make
run_test
log_diffs "SEQ"
log_runtime "SEQ"



