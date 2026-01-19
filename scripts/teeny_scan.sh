#! /usr/bin/bash

function usage() {
echo "Usage: teeny_scan.sh"
}

function run_test() {
    PROG_NAME="$1"
    OUTPUT_FILE="$2"
    EXP_BITS="$3"
    MANT_BITS="$4"

    export FPVM_TEENY_MANT_BITS="$MANT_BITS"
    export FPVM_TEENY_EXP_BITS="$EXP_BITS"

    echo "Running '$PROG_NAME' with EXP=$FPVM_TEENY_EXP_BITS, MANT=$FPVM_TEENY_MANT_BITS"

    timeout 5m fpvm run $PROG_NAME |& tee $OUTPUT_FILE
    if [ "$?" -eq 124 ]; then
	echo "[teeny_scan: TIMEOUT]" >> $OUTPUT_FILE
    fi

    if [ "$?" -eq 0 ]; then
	return 0
    fi
    return -1
}

function scan_prog() {
    PROG_NAME="$1"
    RESULT_DIR="$2"
    mkdir -p "$RESULT_DIR"
    for exponent in $(seq 11 -1 1); do
    for mantissa in $(seq 38 -1 1); do
        run_test $PROG_NAME "$RESULT_DIR/teeny-output.$exponent.$mantissa" $exponent $mantissa
    done
    done
}

SCAN_DIR=./teeny_scan
mkdir -p $SCAN_DIR

RUN_DIR=$SCAN_DIR/run_$(date +%Y%m%d_%H%M%S)
mkdir -p $RUN_DIR
ln -s $RUN_DIR $SCAN_DIR/latest

BENCHMARKS=("./test/nas/bin/bt/bt")

for BENCHMARK in $BENCHMARKS; do
    scan_prog $BENCHMARK $RUN_DIR/$(basename "$BENCHMARK")
done

