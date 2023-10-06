import bshelve as shelve
name = 'enzo-close-storage'
keys = shelve.open(f"{name}-keys", flag='r', writeback=True, loadback=True)
print("number of keys ", len(keys.keys))
nodes = shelve.open(f"{name}-nodes", flag='r', writeback=True, debug=False, preset_keys=keys.keys)
callstacks = shelve.open(f"{name}-callstacks", flag='c', writeback=True, debug=False)
count_g = 0
import threading
LOCK = threading.Lock()
def wrote_callstack(_keys, _nodes):
    sublist = []
    print("how much ", len(_keys))
    for i, key in enumerate(_keys):
        sublist.append( (key, _nodes[key].state.callstack ))
        if i % 1000 == 0:
            print("load tick 1000")

    print("pending")
    LOCK.acquire(True) #blocking acquire
    #got lock
    for key, entry in sublist:
        callstacks[key] = entry
    count_g += len(sublist)
    del sublist
    print("tick ", count_g)
    LOCK.release()
    return    


N = 64 #os.cpu_count() 
all = list(keys.keys)
chunk = int(len(all)/N)+1
size = len(all)
threads = [ threading.Thread(target=wrote_callstack, args=( list(all[i*chunk: min(size, (i+1)*chunk)]), nodes))  for i in range(N) if i*chunk < size]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()

print(f"parallel save done")


# for i, (askey, node) in enumerate(nodes.items()):
#     callstacks[askey] = node.state.callstack
#     if i % 1000 == 0:
#         print(i)

# callstacks.close()

exit()
# nodes_page_keys = shelve.open(f"{name}-page-keys", flag='r', writeback=True, loadback=True, preset_keys=keys.keys)
# extern_keys = shelve.open(f"{name}-extern-keys", writeback=True, loadback=True)
# extern_keys[(0).to_bytes(64, 'big')] = [1,2,3]
# extern_keys.close()

# all_page_key = set()
# for i, (_, page_key_dict) in enumerate( nodes_page_keys.items() ):
#     if i % 10000 == 0:
#         print(i)
#         print(len(all_page_key))
#     for _, states  in page_key_dict.items():
#         for state in states:
#             for _hash in state:
#                 if _hash is not None:
#                     all_page_key.add(_hash)

# print(len(all_page_key))

# extern_keys = shelve.open(f"{name}-extern-keys", writeback=True, loadback=True)
# extern_keys[(0).to_bytes(64, 'big')] = all_page_key
# extern_keys.close()

extern_keys = shelve.open(f"{name}-extern-keys", writeback=True, loadback=False)
all_page_key = extern_keys[(0).to_bytes(64, 'big')]

pages = shelve.open(f"{name}-pages", flag='r', writeback=True, loadback=False, preset_keys=all_page_key)

# print("number of pages ", len(pages))

# pages.close()
# keys.close()
# nodes_page_keys.close()