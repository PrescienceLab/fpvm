#!/usr/bin/env bash

PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")

BIN=$(realpath $1)
DIR=$(dirname $BIN)

pushd $PFX 2>/dev/null
  set -e
  $DIR/time -o generate.timing python3 -m cProfile -o generate.profile parse_vfg.py $BIN 1  #generate vfg
  $DIR/time -o taintsource.timing python3 -m cProfile -o taintsource.profile parse_vfg.py $BIN 0  #generate taint source
  $DIR/time -o taintsink.timing python3 -m cProfile -o taintsink.profile parse_vfg.py $BIN -1 #generate taint sink + e9patch file
popd 2>/dev/null
