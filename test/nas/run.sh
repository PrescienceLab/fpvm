#!/usr/bin/env bash

PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")

source $PFX/../../ENV

for b in mg bt sp lu ft is cg ep; do
  pushd bin/${b}
    # baseline
    fpvm_time.sh ./${b} > ${b}.out 2>&1
    # patched_trap
    fpvm_run.sh ./${b}.patched_trap > ${b}.patched_trap.out 2>&1
    # patched_magic
    fpvm_run.sh ./${b}.patched_magic > ${b}.patched_magic.out 2>&1
  popd



done
