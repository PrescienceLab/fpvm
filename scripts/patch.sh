#!/bin/bash

INPUT=$1
arrIN=(${INPUT//\// })
app=${arrIN[-1]}
app=(${app//\./ })
binary=${app[0]}
echo $binary

cp $INPUT fpvm_static_analysis/XMM_analysis/$binary
pushd fpvm_static_analysis/XMM_analysis

# cleanup from previous runs
rm -f *${binary}_call_patches.csv
rm -f *${binary}_mem_patches.csv
rm -f *${binary}-storage*
rm -f e9patch-${binary}*



python parse_vfg.py ${binary} 1
python parse_vfg.py ${binary} 0
python parse_vfg.py ${binary} -1

bash e9patch-${binary}

popd

cp fpvm_static_analysis/XMM_analysis/a.out $1.patched

echo "dumped pached binary to $1.patched"
