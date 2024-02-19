#/bin/bash

if [ -z "$1" ] ; then
  echo "vis_python_profile.sh <cProfile file>"
  exit -1
fi

pip install gprof2dot --user > /dev/null 2>&1
gprof2dot -f pstats $1 | dot -Tpng -o $1.png
echo your visualization is in $1.png
