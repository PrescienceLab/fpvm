import os
import sys
import angr
import pickle
from angr import SimProcedure
import bshelve as shelve  # berkeley db as backends
import pickle

sys.setrecursionlimit(150)

class DevNull(object):
    def write(self, arg):
        pass
    def flush(self):
        pass

class ExternRange:
    def __init__(self, ranges):
        self.ranges = ranges

    def isextern(self, addr):
        for range in self.ranges:
            if addr <= range[1] and addr >= range[0]:
                return True
        return False


class FakeReturn(SimProcedure):
    def run(self):
        _hook_addr = 0
        print(_hook_addr)
        print("Fake Return at ", hex(_hook_addr))
        return 0




def analyze(binary_path, restart_analysis):
    proj = angr.Project(
        binary_path,
        use_sim_procedures=True,
        default_analysis_mode="symbolic",
        auto_load_libs=False,
        skip_libs={"libm.so.6", "ld-linux-x86-64.so.2", "libgcc_s.so.1"},
    )

    print("proj inited", proj)
    # state = proj.factory.blank_state() # mode="fastpath_static")
    state = proj.factory.blank_state(mode="fastpath_static")
    print(len(pickle.dumps(state, -1)))
    print(len(pickle.dumps(proj.loader, -1)))
    print(len(pickle.dumps(proj.loader.memory, -1)))

    name = str(binary_path).split(".")[0] + "-storage"
    print("proposed name for database ", name)

    extern_ranges = []
    obj = proj.loader.extern_object
    print(obj, obj.min_addr, obj.max_addr)
    extern_ranges.append((obj.min_addr, obj.max_addr))
    extern = ExternRange(extern_ranges)

    print("shared library", proj.loader.shared_objects)

    main = proj.loader.main_object.get_symbol("main")

    cfg = proj.analyses.CFGFast(normalize=True)
    print("cfg done ")

    # start_state = proj.factory.blank_state(addr=main.rebased_addr)

    loops = []

    taint_whole_escape_functions_names = [
        "pow",
        "log",
        "log10",
        "sqrt",
        "__powidf2",
        "ldexp",
        "exp",
        "sin",
        "cos",
        "sincos",
        "tan",
        "asin",
        "acos",
        "atan",
        "sinh",
        "cosh",
        "tanh",
        "asinh",
        "acosh",
        "atanh",
        "atan2",
        "ceil",
        "floor",
        "round",
        "lround",
    ]
    taint_whole_escape_functions = []
    known_functions = []
    known_functions_dict = dict()

    # this is for enzo
    I_dont_want_to_analysis_set_func_name = [
        "fopen",
        "fwrite",
        "fread",
        "fclose",
        "fgetc",
        "fputc",
        "sscanf",
        "unlink",
        "_Z17Group_ReadAllDataPcP14HierarchyEntryR11TopGridDataP16ExternalBoundaryPdb",
        "_Z25auto_show_compile_optionsv",
        "_ZN11enzo_timing10enzo_timer6createEPc",
    ]
    I_dont_want_to_analysis_set_func_addr = []

    for key, func in proj.kb.functions.items():
        if func.name in I_dont_want_to_analysis_set_func_name:
            I_dont_want_to_analysis_set_func_addr.append(func.addr)

        known_functions.append(func.addr)
        known_functions_dict[func.addr] = func.name
        if func.name in taint_whole_escape_functions_names:
            taint_whole_escape_functions.append(func.addr)

    for addr in I_dont_want_to_analysis_set_func_addr:
        proj.hook(addr, FakeReturn())

    known_functions = set(known_functions)
    # remove *-storage before run
    print(" remove *-storage before run again")
    name = str(binary_path).split(".")[0] + "-storage"

    if restart_analysis == 1:
        vfg = proj.analyses.VFG(
            name,
            cfg,
            proj=proj,
            dump_disk=1000,
            FakeReturn=FakeReturn,
            known_functions=known_functions,
            loops=loops,
            start=main.rebased_addr,
            # start = 0x737995,
            # start = 0x68fd0a, #_ZN4grid23ReadRandomForcingFieldsEP8_IO_FILEPc
            context_sensitivity_level=1,
            max_iterations=1,
            interfunction_level=1000,
            remove_options={angr.options.OPTIMIZE_IR},
        )

        nodes = vfg._nodes
        keys = vfg._nodes_keys
        nodes_page_keys = vfg._nodes_page_keys
        pages = vfg._pages
        simp_keys = vfg._simp_keys
        sim_procedures = vfg._sim_procedures

        # I don't want sim anymore
        callstacks = vfg._callstacks
        callstacks.close()
        sim_procedures.cache = None
        sim_procedures.close()

    else:
        print("Skip VSA")
        keys = shelve.open(f"{name}-keys", flag="r", writeback=True, loadback=True)
        print("number of keys ", len(keys.keys))
        nodes = shelve.open(
            f"{name}-nodes",
            flag="r",
            writeback=True,
            debug=False,
            loadback=False,
            preset_keys=keys.keys,
        )
        nodes_page_keys = shelve.open(
            f"{name}-page-keys",
            flag="r",
            writeback=True,
            loadback=True,
            preset_keys=keys.keys,
        )
        # callstacks = shelve.open(f"{name}-callstacks", flag='r', writeback=True, loadback=True, preset_keys=keys.keys)
        if os.path.isfile(f"{name}-extern-keys"):

            extern_keys = shelve.open(
                f"{name}-extern-keys", flag="r", writeback=True, loadback=False
            )
            all_page_key = extern_keys[(0).to_bytes(64, "big")]
        else:
            all_page_key = set()
            for i, (_, page_key_dict) in enumerate(nodes_page_keys.items()):
                if i % 10000 == 0:
                    print("loading page keys ", len(all_page_key))
                for _, states in page_key_dict.items():
                    for state in states:
                        for _hash in state:
                            if _hash is not None:
                                all_page_key.add(_hash)

            print("load done", len(all_page_key))

            extern_keys = shelve.open(
                f"{name}-extern-keys", writeback=True, loadback=True
            )
            extern_keys[(0).to_bytes(64, "big")] = all_page_key
            extern_keys.close()
            extern_keys = shelve.open(
                f"{name}-extern-keys", flag="r", writeback=True, loadback=False
            )
            all_page_key = extern_keys[(0).to_bytes(64, "big")]

        pages = shelve.open(
            f"{name}-pages",
            flag="r",
            writeback=True,
            debug=False,
            loadback=True,
            buffer=30000,
            preset_keys=all_page_key,
        )
        extern_keys.close()


        print("number of pages ", len(pages))

    infos = {
        "nodes": nodes,
        "keys": keys,
        "nodes_page_keys": nodes_page_keys,
        "pages": pages,
        "callstacks": None,  # this is retrieved from keys luckly
        "simp_keys": None,
        "sim_procedures": None,
    }

    return proj, infos, extern, taint_whole_escape_functions, known_functions_dict


from taint_source import taint_source
from taint_sink import taint_sink
from bridge_e9patch import bridge_e9patch

# python parse_vfg.py application 1 --> store vfg in disk
# python parse_vfg.py application 0 --> prepare taint source
# python parse_vfg.py application -1 --> prepare taint sink -> patch file

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Please give a binary path + restart(1) or not(0)")
        exit(0)
    if not os.path.isfile(sys.argv[1]):
        print("File does not exist!")
        exit(0)

    proj, infos, extern, taint_whole_escape_functions, known_functions_dict = analyze(
        sys.argv[1], int(sys.argv[2])
    )

    if int(sys.argv[2]) == 1:
        print("dump into disk")
        for _, toclose in infos.items():
            try:
                toclose.close()
            except:
                pass
        exit()

    print(" begin source analysis")

    filename = os.path.basename(sys.argv[1])

    if int(sys.argv[2]) == 0:
        sources = taint_source(proj, infos)
        with open(f"sources-{filename}", "wb") as f:
            pickle.dump(sources, f, protocol=4)
        exit()

    with open(f"sources-{filename}", "rb") as f:
        sources = pickle.load(f)

    print(sources)
    print(" begin sink analysis")

    sinks, func_sinks = taint_sink(
        proj, infos, sources, extern, taint_whole_escape_functions
    )

    print("=============== output sinks ==========")
    addrs = set([hex(e.address) for e in sinks])
    dicts = dict()
    for e in sinks:
        dicts[hex(e.address)] = e.mnemonic + " " + e.op_str

    for key in dicts.keys():
        print(key, dicts[key])

    exclude_list = ["_Znam", "_Znwm", "_ZdlPv", "memcpy", "memmove", "__stack_chk_fail"]
    to_remove = []
    for key, func in func_sinks.items():
        if known_functions_dict[func] in exclude_list:
            to_remove.append(key)

    for key in to_remove:
        func_sinks.pop(key)

    for site in func_sinks.keys():
        print(f"call at {hex(site)} to {known_functions_dict[func_sinks[site]]}")

    binary_path = sys.argv[1].split("/")[-1]
    binary = str(binary_path).split(".")[0]
    bridge_e9patch(sys.argv[1], filename, sinks, func_sinks, f"e9patch-{filename}")

    for _, toclose in infos.items():
        try:
            toclose.close()
        except:
            pass
