from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

# enum represent xmms
from regs import XMM

# value set is simple representation of possible values contained in xmms
from valueset import ValueSet

# callstack is simple warper to interpret caller callsite, and callee function addr
from helper import CallStack

# sink_interest is whether inst is possibly a sink in it's form. We only care mov from mem to mem/gregs;
# but why?
# e.g.
# func A{
# mov dst, src
# mov mem1, xmm1 // not sink
# mov xmm2, mem1
# mov mem1, mem2 // sink;
# mov greg, mem2 // sink;
# mov xmm3, mem2
# }
from helper import sink_interest

# taint func means, whthin func A, if A calls function that is not analysed (e.g. extern lib),
# the whole func is taint func
from helper import taint_functions


# @proj, angr proj
# @info, angr states of insns
# @source, taint sources is address of var that load into xmm; if var is stored into greps, it's sink
# @upto is how many possible values for regs/mem you want to retrieve
# @taint_whole_escape_functions is if A only calls func in taint_whole_escape_functions; A is not taint func
def taint_sink(
    proj, infos, sources, extern_functions, taint_whole_escape_functions, upto=1
):

    # nodes is block_id->inst_state; block is inst level
    # keys is block_id_key -> block_id; why this? to fast load key from disk
    # nodes_page_keys -> block_id_ky -> pages_hashs; why this? to fast load page_hash from disk
    # pages_hash -> real_pages; real_pages are what inst_state uses
    # sim means sim_procedure, normally for functions, NOT used
    nodes, keys, nodes_page_keys, pages, simp_keys, sim_procedures, callstacks = (
        infos["nodes"],
        infos["keys"],
        infos["nodes_page_keys"],
        infos["pages"],
        infos["simp_keys"],
        infos["sim_procedures"],
        infos["callstacks"],
    )

    # flatten into a set
    all_taint_sources = sources.flatten()
    sinks = []
    last_state = None

    sortedlist = sorted(keys.items(), key=lambda item: (item[1].addr))

    func_sinks = dict()
    # gather functions
    funcs = []
    for key, func in proj.kb.functions.items():
        if len(func.block_addrs_set) > 0:
            # this capture start of func, and end of func; might be BOGUS for end
            funcs.append((func.addr, max(list(func.block_addrs_set))))
        else:
            # no blocks for this func; wired;
            pass

    # taint func means, whthin func A, if A calls function that is not analysed (e.g. extern lib),
    # the whole func is taint func
    # extern_functions is e.g. printf etc. that are not analysed
    # BOGUS, likely extern_func doesn't cover all, like printf ----> fix that
    taint_func, extern_func = taint_functions(
        proj, sortedlist, extern_functions, taint_whole_escape_functions
    )

    last_addr = 0
    SKIP_COUNT = 0

    # askey is a real hash key
    # key is block id as a key; key == blockid
    for node_idx, (askey, blockid) in enumerate(sortedlist):

        callstack = CallStack(blockid.callsite_tuples[-2:])

        if blockid.addr == last_addr:
            continue
        else:
            last_addr = blockid.addr

        taint_whole = False
        if callstack.func_addr in taint_func:
            # to be more accurate, we could use reaching definition here to rule out latest xmm0-xmm15
            taint_whole = True
        else:
            taint_whole = False

        # you can disable taint_whole for now
        #  taint_whole = False
        # what does taint_whole mean ?
        # e.g.
        #  function A {
        #    movq greg, xmm     //normally this is NOT sink point as grep might be loaded back
        #    printf()           // however, because printf is not analysed, greg might be used
        #    movq grep2, xmm    // grep is sink, so we should check
        #    ret                // because we don't have resolution for where printf is happening
        #                       // movq grep2, xmm is a sink point as well
        #                       // disable taint_whole means we don't care about this for now
        # }

        block = proj.factory.block(blockid.addr)
        insns = block.disassembly.insns  # extract the only insn from block

        if len(insns) == 0:
            continue
        else:
            insn = insns[0]
        print(insn)

        if not sink_interest(insn) and taint_whole is False:
            SKIP_COUNT += 1
            if SKIP_COUNT % 1000 == 0:
                print("SKIPPED ", SKIP_COUNT)
            continue

        # states correspond to insn
        node = nodes[askey]

        # multiple final states due to merging
        if len(node.final_states) >= 1:

            # recover from disk
            node.recover_from_dump(
                proj, askey, nodes_page_keys, pages, None, None, True
            )
            state = node.final_states[0]

            # whats last insn, retrieve its state as last_state
            if last_state is None:
                _use_idx = max(node_idx - 1, 0)
                _askey, _ = sortedlist[_use_idx]
                _node = nodes[_askey]
                if len(_node.final_states) >= 1:
                    _node.recover_from_dump(
                        proj, _askey, nodes_page_keys, pages, None, None, True
                    )
                    _state = _node.final_states[0]
                    last_state = _state

            # handle calling a function which calls into a unsoveled function
            if (
                insn.mnemonic == "call" or "j" in insn.mnemonic
            ):  # call or any sorts of jumps

                if insn.operands[0].type == X86_OP_IMM:

                    # this is not complete, what if call *rax
                    call_to = insn.operands[0].imm
                    if call_to in extern_func:
                        func_sinks[insn.address] = call_to

            if len(insn.operands) > 1:  # dst, src1, src2 ...

                if taint_whole:
                    skip = False
                    for i in insn.operands:
                        if i.type == X86_OP_REG and "xmm" in insn.reg_name(i.reg):
                            skip = ~skip

                    # enforce src is xmm
                    if (
                        skip
                        and insn.operands[0].type == X86_OP_REG
                        and "xmm" in insn.reg_name(insn.operands[0].reg)
                    ):
                        skip = False

                    if skip:
                        # maybe a sink, maybe not; but it's taint_whole, so we need it.
                        # you can disable this to reduce sinks
                        sinks.append(insn)
                        continue

                value_set = ValueSet([0])
                if not sink_interest(insn):
                    last_state = state
                    continue

                for idx, i in enumerate(insn.operands):

                    use_state = state
                    if idx > 0:
                        use_state = last_state
                    else:
                        # why would you care about destination, which is going to be overwrite anyway
                        continue
                    # if len(insn.operands) == 1:
                    #     i = insn.operands[0]
                    # else:
                    #     i = insn.operands[1]
                    if i.type == X86_OP_REG:
                        reg = insn.reg_name(i.reg)
                        try:
                            value_set = ValueSet(
                                use_state.solver.eval_upto(
                                    getattr(use_state.regs, reg), upto
                                )
                            )
                            print(value_set)
                            # value = use_state.solver.eval(getattr(use_state.regs, reg))
                        except Exception:
                            print(f"fail {reg} and set to 0")
                            value_set = ValueSet([0])

                        # print(insn.mnemonic, )

                    elif i.type == X86_OP_IMM:
                        value_set = ValueSet([i.imm])

                        # print(insn.mnemonic, value_set)

                    elif i.type == X86_OP_MEM:
                        if insn.reg_name(i.mem.index) != None:
                            reg = insn.reg_name(i.mem.index)

                            try:
                                index = ValueSet(
                                    use_state.solver.eval_upto(
                                        getattr(use_state.regs, reg), upto
                                    )
                                )
                                index_expr = getattr(use_state.regs, reg)
                            except Exception:
                                index = ValueSet([0])
                                index_expr = 0

                        else:
                            index = ValueSet([i.mem.index])
                            index_expr = i.mem.index

                        if insn.reg_name(i.mem.scale) != None:
                            reg = insn.reg_name(i.mem.scale)
                            try:
                                scale = ValueSet(
                                    use_state.solver.eval_upto(
                                        getattr(use_state.regs, reg), upto
                                    )
                                )
                                scale_expr = getattr(use_state.regs, reg)

                            except Exception:
                                print(f"scale except of {reg}, set to 0")
                                scale = ValueSet([0])
                                scale_expr = 0
                        else:
                            scale = ValueSet([i.mem.scale])
                            scale_expr = i.mem.scale
                        # if insn.reg_name(i.mem.disp) != None:
                        #     reg = insn.reg_name(i.mem.scale)
                        #     disp = use_state.solver.eval(getattr(use_state.regs, reg ))
                        # else:
                        disp = ValueSet([i.mem.disp])
                        disp_expr = i.mem.disp

                        offset = index * scale + disp
                        # print( insn.reg_name(i.mem.segment), insn.reg_name(i.mem.base) )
                        if insn.reg_name(i.mem.segment) != None:
                            reg = insn.reg_name(i.mem.segment)
                        else:
                            # print("regstate", regstate.access(insn.reg_name(i.mem.base)) )
                            reg = insn.reg_name(i.mem.base)

                        try:
                            base = ValueSet(
                                use_state.solver.eval_upto(
                                    getattr(use_state.regs, reg), upto
                                )
                            )
                            base_expr = getattr(use_state.regs, reg)
                        except Exception:
                            base = ValueSet([0])
                            base_expr = 0

                        value_set = base + offset
                        # print(insn.mnemonic, value_set)

                    if (
                        sink_interest(insn)
                        and len(value_set._set.intersection(all_taint_sources)) != 0
                    ):
                        sinks.append(insn)
                        break

            last_state = state
        else:
            last_state = None

    return sinks, func_sinks
