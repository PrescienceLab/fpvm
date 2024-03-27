#!/usr/bin/env bash

PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")


mkdir -p /root/workspace
cp /root/output/input /root/workspace/input
BIN=/root/workspace/input


pushd $PFX 2>/dev/null
  set -e
  /usr/bin/time -o generate.timing python3 parse_vfg.py $BIN 1 2>&1 >> /root/output/patch.log #generate vfg
  /usr/bin/time -o taintsource.timing python3 parse_vfg.py $BIN 0 2>&1 >> /root/output/patch.log #generate taint source
  /usr/bin/time -o taintsink.timing python3 parse_vfg.py $BIN -1 2>&1 >> /root/output/patch.log #generate taint sink + e9patch file
  ls -la /root/analysis/src/ > /root/output/cont
popd 2>/dev/null


cp /root/analysis/src/*_patches.csv /root/output/
# RUN cp /root/analysis/src/*.profile /root/output/
cp /root/analysis/src/*.timing /root/output/
