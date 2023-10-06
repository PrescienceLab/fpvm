
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from regs import XMM
from valueset import ValueSet 
from helper import CallStack
from helper import TaintState
from helper import init_source_key
from helper import wrap
from helper import sink_interest
from helper import taint_functions

def should_skip(source_key, taint_whole, sink_interested):
    if source_key is None and taint_whole is False and sink_interested is False:
        return True
    return False

def taint_source_sink(proj, infos, extern_functions, taint_whole_escape_functions,  upto=1):

    SKIP_COUNT = 0

    nodes, keys, nodes_page_keys, pages, simp_keys , sim_procedures = infos['nodes'], infos['keys'], infos['nodes_page_keys'],infos['pages'],infos['simp_keys'],infos['sim_procedures'],
    taint_state = TaintState()
    last_state = None
    sortedlist = sorted( keys.items(), key=lambda item: (item[1].addr) )
    
    #handle special calling into extern functions
    taint_func = taint_functions(proj, sortedlist, extern_functions, taint_whole_escape_functions)
    
    last_addr = 0

    count = 0
    for node_idx, (askey, key) in enumerate(sortedlist):
        if key.addr == last_addr:
            continue 
        else:
            last_addr = key.addr

        block = proj.factory.block(key.addr)
        insns = block.disassembly.insns
        if len(insns) == 0:
            continue
        else:
            insn = insns[0]
        
        print(insn)

        if len(insn.operands) <= 0:
            continue

        callstack = CallStack(key.callsite_tuples[-2:])

        taint_whole = False
        if callstack.func_addr in taint_func:
            taint_whole = True
        else:
            taint_whole = False

        source_key, insert_place = init_source_key(insn) 
        sink_interested = sink_interest(insn)
        skip = should_skip(source_key, taint_whole, sink_interested)

        if skip:
            SKIP_COUNT += 1
            if SKIP_COUNT % 1000 == 0:
                print("SKIPPED ", SKIP_COUNT)
            continue

        # defer retrieve of node, because this is heavy
        node = nodes[askey]
        # locate the instruction , this line is not correct
        print(f"separate====== {len(node.final_states)}")
        if len(node.final_states) >= 1:
            node.recover_from_dump(proj, askey, nodes_page_keys, pages, None, None, True)
            state = node.final_states[0]
            
            if len(insn.operands) > 0:
                source_key, insert_place = init_source_key(insn) 
                value = 0

                if last_state is None:
                    _use_idx = max( node_idx - 1, 0)
                    _askey, _key = sortedlist[_use_idx]
                    _node = nodes[_askey]
                    if len(_node.final_states) >= 1:
                        _node.recover_from_dump(proj, _askey, nodes_page_keys, pages, None, None, True)
                        _state = _node.final_states[0]
                        last_state = _state 
                use_state = state

                for idx, i in enumerate(insn.operands):
                    if idx > 0:
                        use_state = last_state
                
                    if i.type == X86_OP_REG:
                        reg = insn.reg_name(i.reg)
                        # print()
                        # print(getattr(state.regs, reg))
                        try:
                            value_set = ValueSet(use_state.solver.eval_upto(getattr(use_state.regs, reg), upto))
                            # print(value_set)
                            # value = use_state.solver.eval(getattr(use_state.regs, reg))
                        except Exception:
                            print(f"fail {reg} and set to 0")
                            value_set = ValueSet([0])

                        print(insn.mnemonic, value_set)

                    elif i.type == X86_OP_IMM:
                        value_set = ValueSet([i.imm])

                        print(insn.mnemonic, value_set)

                    elif i.type == X86_OP_MEM:
                        if insn.reg_name(i.mem.index) != None:
                            reg = insn.reg_name(i.mem.index)
                            try:
                                index = ValueSet( use_state.solver.eval_upto(getattr(use_state.regs, reg), upto))
                                index_expr = getattr(use_state.regs, reg)
                            except Exception:
                                index = ValueSet([0])
                                index_expr = 0

                        else:
                            index =  ValueSet([i.mem.index])
                            index_expr =  i.mem.index
                        
                        if insn.reg_name(i.mem.scale) != None:
                            reg = insn.reg_name(i.mem.scale)
                            
                            try:
                                scale = ValueSet(use_state.solver.eval_upto(getattr(use_state.regs, reg), upto))
                                scale_expr = getattr(use_state.regs, reg)

                            except Exception:
                                print(f"scale except of {reg}, set to 0")
                                scale = ValueSet([0])
                                scale_expr = 0
                        else:
                            scale =  ValueSet([i.mem.scale])
                            scale_expr = i.mem.scale
                        
                        # is it possible that disp is reg ???
                        # if insn.reg_name(i.mem.disp) != None:
                        #     reg = insn.reg_name(i.mem.scale)
                        #     disp = use_state.solver.eval(getattr(use_state.regs, reg ))
                        # else:
                        disp =  ValueSet([i.mem.disp]) 
                        disp_expr = i.mem.disp

                        offset = index * scale + disp
                        # print( insn.reg_name(src.mem.segment), insn.reg_name(src.mem.base) )
                        if insn.reg_name(i.mem.segment) != None:
                            reg = insn.reg_name(i.mem.segment)
                        else:
                            # print("regstate", regstate.access(insn.reg_name(i.mem.base)) )
                            reg = insn.reg_name(i.mem.base)
                        try: 
                            base = ValueSet( use_state.solver.eval_upto(getattr(use_state.regs, reg ), upto))
                            base_expr = getattr(use_state.regs, reg )
                        except Exception:
                            print("fail ", reg, "set to 0")
                            base = ValueSet([0])
                            base_expr = 0
                        value_set = base + offset
                        # print(base_expr, disp_expr)
                        # print(insn.mnemonic,value, "base", base, "offset", offset, "index", index, "scale", scale, "disp", disp)
                        
                        # if use_state.mem[base_expr+disp_expr].resolvable: 

                        try:
                            # if use_state.mem[base_expr+disp_expr].resolvable: 
                            # bogus use base_expr+index_expr*scale_expr+disp_expr instead
                            mem_vset = ValueSet( use_state.solver.eval_upto(use_state.mem[base_expr+disp_expr].uint64_t.resolved, upto))
                            value_set |= mem_vset
                        except Exception as e:
                            print("retrieve mem error", e)

                        print( insn.mnemonic, value_set)

                    if source_key and idx == insert_place:
                        ori_value = getattr(taint_state, source_key)
                        setattr(taint_state, source_key, value_set._set | ori_value )

            last_state = state
        else:
            print("reset")
            last_state = None

    return taint_state                
                    # elif i.type == 
            # a.op_str
            # print(state.memory)
            