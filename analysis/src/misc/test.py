import bshelve
a = 1
key = a.to_bytes(64,'big', signed=True)
dict_ = bshelve.open("ddd", writeback=True)
data = [1,2,3,3,4,5]
dict_[key] = data
# dict_.sync()
print(dict_.cache)
print( dict_[key] )
del dict_[key]
print("done")
print(data)