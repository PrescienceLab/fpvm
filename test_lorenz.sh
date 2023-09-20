#!/bin/bash



# make sure the lorenz binaries are up to date
make test/lorenz_attractor.patched

mkdir -p data/lorenz

test/lorenz_attractor > data/lorenz/base.csv
./run.sh test/lorenz_attractor.patched > data/lorenz/fpvm.csv

LD_PRELOAD=build/fpvm.so FPVM_AGRESSIVE=y $@
