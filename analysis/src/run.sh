#!/usr/bin/env bash

PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")

BIN=$(realpath $1)
DIR=$(dirname $BIN)

pushd $PFX 2>/dev/null
  set -e
  /usr/bin/time -o generate.timing python3 parse_vfg.py $BIN 1  #generate vfg
  /usr/bin/time -o taintsource.timing python3 parse_vfg.py $BIN 0  #generate taint source
  /usr/bin/time -o taintsink.timing python3 parse_vfg.py $BIN -1 #generate taint sink + e9patch file
popd 2>/dev/null
