import numpy as np 
import re
import sys

directory = sys.argv[1]
names = ["decoder cache", "decoder", "bind", "emulate", "gc", "patch"]
filenames = ["dcache", "decoder", "bind", "emulate", "gc", "patch"]
np_dict = dict()
for file, name in zip(filenames, names):
    arr = []
    with open(f"{directory}/{file}", "r") as f:
        for line in f.readlines():
            res = re.split("[[a-zA-Z| |:]+[0-9]?=", line.strip())
            tmp = []
            try:
                # ignore first which is blank; fix later
                for ele in res[1:]:
                    if '.' in ele:
                        tmp.append(float(ele))
                    else:
                        tmp.append(int(ele))
            except:
                print(res)
                break
            arr.append(tmp)    
    np_dict[name] = np.array(arr)

#use sum only
for name in names:
    print(name, np_dict[name][-1][1])
