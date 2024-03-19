#!/usr/bin/env bash

CLASS=S
#
# make BT CLASS=$CLASS; mkdir bin/bt; mv bin/bt* bin/bt
# make SP CLASS=$CLASS; mkdir bin/sp; mv bin/sp* bin/sp
# make LU CLASS=$CLASS; mkdir bin/lu; mv bin/lu* bin/lu
# make MG CLASS=$CLASS; mkdir bin/mg; mv bin/mg* bin/mg
# make FT CLASS=$CLASS; mkdir bin/ft; mv bin/ft* bin/ft
# make IS CLASS=$CLASS; mkdir bin/is; mv bin/is* bin/is
# make CG CLASS=$CLASS; mkdir bin/cg; mv bin/cg* bin/cg
# make EP CLASS=$CLASS; mkdir bin/ep; mv bin/ep* bin/ep
#
# exit

cp config/make-clang.def config/make.def

make ${b^^} CLASS=$CLASS clean

for b in mg bt sp lu ft is cg ep; do
  mkdir -p bin/${b}
  pushd bin/${b}
    rm -f *
  popd
done
