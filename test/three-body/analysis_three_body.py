import numpy as np 
import pandas as pd
import re
import sys
import matplotlib.pyplot as plt

arr = []
arr2 = []
directory = sys.argv[1]
filenames = "three_body_simulation_y.txt"
stats = dict()

ndarr = pd.read_csv(f"{directory}/{filenames}", header=None).to_numpy()[:, :-1]
plt.plot(ndarr[:,0], ndarr[:, 1])
plt.plot(ndarr[:,0+4], ndarr[:,1+4])
plt.savefig("trace.png")


# alive = df[" alive"].to_numpy()[1:] #first one is meaning less
# freed = df[" freed"].to_numpy()[1:]
# latency = df[" gc_latency (us)"].to_numpy()[1:]
# print("alive,", alive.mean(), alive.std())
# print("freed,", freed.mean(), freed.std())
# print("latency(us),", latency.mean(), latency.std())

# with open(f"{file}", "r") as f:
#     for line in f.readlines():
#         res = line.strip().split(",")
#         if len(res) == 3:
#             arr2.append([int(res[1]), int(res[2])])
#         else:
#             arr.append([int(res[0]), int(res[1])])

# to_sigfpe = np.array(arr)
# from_sigfpe = np.array(arr2)

# to_sigfpe_time = []
# from_sigfpe_time = []
# for outside, inside  in zip(to_sigfpe, from_sigfpe):
#     to_sigfpe_time.append( inside[0]-outside[0] )
#     from_sigfpe_time.append(outside[1]-inside[1])

# to_sigfpe_time = np.array(to_sigfpe_time)
# from_sigfpe_time = np.array(from_sigfpe_time)
# print(len(to_sigfpe_time[10000:-10000]))
# print(to_sigfpe_time[10000:-10000].mean())
# print(from_sigfpe_time[10000:-10000].mean())
