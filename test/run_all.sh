#!/usr/bin/env bash

export FPVM_HOME=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/../")
source ${FPVM_HOME}/ENV


mkdir -p ${FPVM_HOME}/results
NAS_CLASS=S

buildstep() {
    NAME=$1
    shift
    "$@" 2>&1 | sed $'s|^|\x1b[34m['"${NAME}"$']\x1b[39m |' || exit 1
}

function run_test {
  name=$1
  binary=$2

  echo $name $binary
  buildstep ${name} fpvm benchmark -c 1 --output=${FPVM_HOME}/results/${name} ${binary}
}


pushd ${FPVM_HOME}/test/nas
  make clean
  cp config/make-gcc.def config/make.def

  for b in mg bt sp lu ft is cg ep; do
    make ${b^^} CLASS=$NAS_CLASS
    mkdir -p bin/${b}
    mv bin/${b}.${NAS_CLASS} bin/${b}/${b}
  done


  for b in mg bt sp lu ft is cg ep; do
    run_test "nas_${b}" bin/${b}/${b}
  done
popd



make -C ${FPVM_HOME}/test/lorenz lorenz_attractor
run_test lorenz ${FPVM_HOME}/test/lorenz/lorenz_attractor


make -C ${FPVM_HOME}/test/double_pendulum double_pendulum
run_test double_pendulum ${FPVM_HOME}/test/double_pendulum/double_pendulum

make -C ${FPVM_HOME}/test/fbench fbench
run_test fbench ${FPVM_HOME}/test/fbench/fbench

make -C ${FPVM_HOME}/test/ffbench ffbench
run_test ffbench ${FPVM_HOME}/test/ffbench/ffbench

make -C ${FPVM_HOME}/test/three-body three_body_simulation
run_test three-body ${FPVM_HOME}/test/three-body/three_body_simulation
