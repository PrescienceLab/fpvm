#!/bin/bash

if [ -z "$1" ] ; then
  echo "fpvm_time.sh <command>"
  exit -1
fi    

time $@

