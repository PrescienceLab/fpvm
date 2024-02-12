#!/usr/bin/env bash

PFX=$(realpath "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )")


OLD_DIR=$PWD
BIN=$(realpath $1)

pushd ${PFX} 2>/dev/null
  # Delete the old workspace folder
  rm -rf workspace
  # Make a new one
  mkdir -p workspace
  # Copy the binary into the right location
  cp $BIN workspace/input
  # Run the patch
  docker buildx build --progress=plain -o workspace/ .

  cp workspace/input.patched ${BIN}.patched
popd 2>/dev/null
