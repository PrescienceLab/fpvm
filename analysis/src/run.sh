#!/usr/bin/env bash

PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")

BIN=$(realpath $1)

pushd $PFX 2>/dev/null
  set -e
  python3 parse_vfg.py $BIN 1  #generate vfg
  python3 parse_vfg.py $BIN 0  #generate taint source
  python3 parse_vfg.py $BIN -1 #generate taint sink + e9patch file
popd 2>/dev/null
