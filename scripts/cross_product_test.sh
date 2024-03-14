#!/bin/bash

fixed_options=(
  "#define CONFIG_NO_OUTPUT 0"
  "#define CONFIG_DEBUG 0"
  "#define CONFIG_DEBUG_ALT_ARITH 0"
  "#define CONFIG_TELEMETRY 0"
  "#define CONFIG_PERF_STATS 0"
  "#define CONFIG_INSTR_TRACES 0"
  "#define CONFIG_ALT_MATH_VANILLA 0"
  "#define CONFIG_ALT_MATH_BOXED_IEEE 1"
  "#define CONFIG_ALT_MATH_POSIT 0"
  "#define CONFIG_ALT_MATH_MPFR 0"
  "#define CONFIG_ALT_MATH_RATIONAL 0"
  "#define CONFIG_KERNEL_SHORT_CIRCUITING 0"
)

var_options=(
  "#define CONFIG_INSTR_SEQ_EMULATION 0\n#define CONFIG_MAGIC_CORRECTNESS_TRAP 0\n"
  "#define CONFIG_INSTR_SEQ_EMULATION 0\n#define CONFIG_MAGIC_CORRECTNESS_TRAP 1\n"
  "#define CONFIG_INSTR_SEQ_EMULATION 1\n#define CONFIG_MAGIC_CORRECTNESS_TRAP 0\n"
  "#define CONFIG_INSTR_SEQ_EMULATION 1\n#define CONFIG_MAGIC_CORRECTNESS_TRAP 1\n"
)

if [[ -z "${FPVM_HOME}" ]]; then
  echo "Please source ENV at the root of the FPVM dir"
  exit -1
fi

config_file=$FPVM_HOME/include/fpvm/config.h
test_dir=$FPVM_HOME/test/lorenz
benchmark="lorenz_attractor"
diff_output_file=TEST_DIFFS.out

mv $test_dir/TEST_DIFFS.out $test_dir/TEST_DIFFS.out.old

for i in "${var_options[@]}"
do
  printf "%s\n" "${fixed_options[@]}" > $config_file
  echo -e "$i" >> $config_file
  echo "#define CONFIG_TRAP_SHORT_CIRCUITING 0" >> $config_file
  make clean
  make

  pushd $test_dir

  make
  make test
  diff $test_dir/$benchmark.out $test_dir/$benchmark.patched_trap.out >> $diff_output_file
  diff $test_dir/$benchmark.out $test_dir/$benchmark.patched_magic.out >> $diff_output_file
  echo -e "\n\n" >> $diff_output_file

  popd
done

# KERNEL TESTING

echo "BEGINNING KERNEL TESTS"
echo "DO NOT RUN THIS ON ROQUEFORT (ONLY JARLSBERG)"
# saving lives
if [ `hostname` != "jarlsberg" ]; then
  exit -1
fi

pushd kernel/
sudo ./kmod_build.sh
sudo ./kmod_setup.sh
popd

for i in "${var_options[@]}"
do
  printf "%s\n" "${fixed_options[@]}" > $config_file
  echo -e "$i" >> $config_file
  echo "#define CONFIG_TRAP_SHORT_CIRCUITING 1" >> $config_file
  make clean
  make

  pushd $test_dir

  make
  make test
  diff $test_dir/$benchmark.out $test_dir/$benchmark.patched_trap.out >> $diff_output_file
  diff $test_dir/$benchmark.out $test_dir/$benchmark.patched_magic.out >> $diff_output_file
  echo -e "\n\n" >> $diff_output_file

  popd
done

sudo rmmod fpvm_dev
