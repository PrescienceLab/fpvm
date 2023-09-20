#!/bin/bash

export BASE="/home/fpvm/fpvm2"
export BINS=$BASE/test/ALL_BIN
export OUTPUT_DIR=$BASE/test_output
export LD_LIBRARY_PATH=$BASE/lib:$LD_LIBRARY_PATH


export OMP_NUM_THREADS=1
export LD_LIBRARY_PATH=/home/fpvm/NPB3.0-omp-C:/$LD_LIBRARY_PATH

export LD_LIBRARY_PATH=/home/fpvm/enzo_libs/HDF5/lib:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/home/fpvm/enzo_libs/LIBRARIES/lib:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/home/fpvm/enzo_libs/HYPRE/lib:$LD_LIBRARY_PATH
export LOCAL_HYPRE_INSTALL=/home/fpvm/enzo_libs/HYPRE
export LOCAL_HDF5_INSTALL=/home/fpvm/enzo_libs/HDF5
# Spack Stuff
export LD_LIBRARY_PATH=/home/fpvm/spack/opt/spack/linux-ubuntu16.04-x86_64/gcc-5.4.0/openmpi-3.1.4-sicgfupfimot6tftveifjouohnrjtbds/lib:$LD_LIBRARY_PATH
export PATH=/home/fpvm/spack/opt/spack/linux-ubuntu16.04-x86_64/gcc-5.4.0/openmpi-3.1.4-sicgfupfimot6tftveifjouohnrjtbds/bin:$PATH
export LD_LIBRARY_PATH=/home/fpvm/spack/opt/spack/linux-ubuntu16.04-x86_64/gcc-5.4.0/hwloc-1.11.11-ocnpnjepihxrs3qvbx2usdyju62aauq7/lib:$LD_LIBRARY_PATH

if [[ "$#" -ne 1 ]]; then
	echo "Usage: ./run.sh <test_name>"
	echo "Valid Test Names: fbench, three-body, lorenz, enzo, nas"
	exit -1
fi

if [[ $@ == "fbench" ]]; then
	echo "Running fbench_patched" 
	cd $OUTPUT_DIR/fbench
	LD_PRELOAD=$BASE/build/fpvm.so FPVM_DISABLE_PTHREADS=y FPVM_AGGRESSIVE=y $BINS/fbench/fbench_patched
elif [[ $@ == "three-body" ]]; then
	echo "Running three_body_simulation.patched" 
	cd $OUTPUT_DIR/three-body
	LD_PRELOAD=$BASE/build/fpvm.so FPVM_DISABLE_PTHREADS=y FPVM_AGGRESSIVE=y $BINS/three-body/three_body_simulation.patched
elif [[ $@ == "lorenz" ]]; then
	echo "Running lorenz_attractor.patched" 
	cd $OUTPUT_DIR/lorenz
	LD_PRELOAD=$BASE/build/fpvm.so FPVM_DISABLE_PTHREADS=y FPVM_AGGRESSIVE=y $BINS/lorenz/lorenz_attractor.patched
elif [[ $@ == "enzo" ]]; then
	echo "Running enzo_patched" 
	cd $OUTPUT_DIR/enzo

	LD_PRELOAD=$BASE/build/fpvm.so FPVM_AGGRESSIVE=y $BINS/enzo/enzo_patched $BINS/enzo/input
elif [[ $@ == "nas" ]]; then
	echo "Running nas/cg.S.patched"
	cd $OUTPUT_DIR/nas


	LD_PRELOAD=$BASE/build/fpvm.so FPVM_DISABLE_PTHREADS=y FPVM_AGGRESSIVE=y $BINS/nas/cg.S.patched
else
	echo "Invalid test name"
	echo "Valid Test Names: fbench, three-body, lorenz, enzo, nas"
	exit -1
fi



