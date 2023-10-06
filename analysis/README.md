# How to run the static analysis

In the analysis folder, grab dependencies and build them with make:
```
make dep
```

Then install the python dependencies
```
pip install -r requirements.txt --no-cache-dir
```


You can then run the patcher as follows:
```
cd src
python parse_vfg.py <binary> 1  #generate vfg
python parse_vfg.py <binary> 0  #generate taint source
python parse_vfg.py <binary> -1 #generate taint sink + e9patch file
```


or, from anywhere run the `patch.sh` script:

```
./patch.sh binary
```
which will produce `binary.patched`
