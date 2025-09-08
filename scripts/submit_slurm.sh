#!/usr/bin/env bash



export FPVM_HOME=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/../")

# Make sure the venv has all the packages
pip3 install -r requirements.txt
# Build FPVM
make -j $(nproc)
# Build the tests
make -j -C test/

function run_test {
  mkdir -p slurm-output
  name=$1
  binary=$2

  sbatch --exclusive -w $(hostname) \
         -o slurm-output/${name}.out -e slurm-output/${name}.err \
         -J "FPVM ${name}" --wrap "fpvm benchmark -c 8 --output=output/${name} ${binary}"
}


pushd ${FPVM_HOME}
    run_test lorenz test/lorenz/lorenz_attractor
    run_test three-body test/three-body/three_body_simulation
    run_test double_pendulum test/double_pendulum/double_pendulum
    run_test fbench test/fbench/fbench
    run_test ffbench test/ffbench/ffbench
popd


pushd ${FPVM_HOME}/test/nas
  make clean
  cp config/make-gcc.def config/make.def

  for b in mg bt sp lu ft is cg ep; do
    # Don't recompile if you don't need to
    if [ ! -e bin/${b}/${b} ]; then
      make ${b^^} CLASS=$NAS_CLASS
      mkdir -p bin/${b}
      mv bin/${b}.${NAS_CLASS} bin/${b}/${b}
    fi
  done

  for b in mg bt sp lu ft is cg ep; do
    run_test "nas_${b}" bin/${b}/${b}
  done
popd
