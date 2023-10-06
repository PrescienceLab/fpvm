
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from regs import XMM
from valueset import ValueSet

def not_floating_instruction(insn):
    ans = False
    
    for idx, oprand in enumerate(insn.operands):
        if oprand.type == X86_OP_REG:
            reg = insn.reg_name(oprand.reg)
            if "xmm" in reg:
                return False
        
        #src has to be a mem location; capture load only
        if idx == 1:
            if oprand.type != X86_OP_MEM:
                return False

        #dst is reg; return False; want to capture write to memory
        # if idx == 0:
        #     if oprand.type == X86_OP_REG:
        #         return False

    if 'lea' in insn.mnemonic:
        ans = False
    else:
        ans = True

    return ans 

def taint_sink(proj, nodes, sources, extern_functions, taint_whole_escape_functions, upto=5):
    all_taint_sources = sources.flatten()
    sinks = []
    last_state = None
    sortedlist = sorted( nodes.items(), key=lambda item: (item[0].addr) )
    func_sinks = dict()
    #handle special calling into extern functions

    #gather functions
    funcs = []
    for key, func in proj.kb.functions.items():
        if len(func.block_addrs_set) > 0:
            print("func, ", hex(func.addr))
            funcs.append( (func.addr, max(list( func.block_addrs_set))))
        else:
            print("no blocks ", hex(func.addr))

    taint_func = []
    extern_func = []
    for key, node in sortedlist:
       
        if extern_functions.isextern(node.addr):
            if node.state.callstack.func_addr in taint_whole_escape_functions:
                print("skip taint whole", node.state.callstack.func_addr)
                continue
            call_site = node.state.callstack.call_site_addr
            extern_func.append(node.state.callstack.func_addr)
            func_sinks[node.state.callstack.call_site_addr] = node.state.callstack.func_addr

            print("extern -----------" ,hex(node.addr), "called at", hex(call_site) ) 
            for start, end in funcs:
                # print(hex(start), hex(end))
                if call_site <= end and call_site >= start:
                    #mark the funcitons as taint
                    # print(f"++++++ funciton {hex(start)} is taint_whole")
                    taint_func.append(start)
    
    taint_func = set(taint_func)
    
    for key, node in sortedlist:
        # locate the instruction , this line is not correct
        # if fun_fun.addr in key:
        # print(hex(key.addr), node)
        print("separate======")
        taint_whole = False
        if node.state.callstack.func_addr in taint_func:
            #to be more accurate, we could use reaching definition here to rule out latest xmm0-xmm15
            taint_whole = True
            # if node.addr == node.state.callstack.func_addr:
            #     if node.state.callstack.call_site_addr is not None:
            #         func_sinks[node.state.callstack.call_site_addr] = node.state.callstack.func_addr


        else:
            taint_whole = False
       

        if len(node.final_states) >= 1:
            state = node.final_states[0] #extract the only state from final_states
            if last_state is None:
                last_state = state 
            block = proj.factory.block(key.addr)
            insns = block.disassembly.insns #extract the only insn from block
            
            if len(insns) == 0:
                continue
            else:
                insn = insns[0]
            print(insn)
            
            #handle calling a function which calls into a unsoveled function
            if insn.mnemonic == 'call':
                if insn.operands[0].type == X86_OP_IMM:
                    call_to = insn.operands[0].imm
                    if call_to in extern_func:
                        func_sinks[insn.address] = call_to

            if len(insn.operands) > 1:

                if taint_whole:
                    skip = False
                    for i in insn.operands:
                        if  i.type == X86_OP_REG and 'xmm' in insn.reg_name(i.reg):
                            skip = ~skip

                    #enforce src is xmm    
                    if skip and insn.operands[0].type == X86_OP_REG and 'xmm' in insn.reg_name(insn.operands[0].reg):
                        skip = False
                    
                    if skip:
                        sinks.append(insn)
                        continue 

                value_set = ValueSet([0])
                for idx, i in enumerate(insn.operands):
                    
                    use_state = state
                    if idx > 0:
                        use_state = last_state
                    else:
                        #why would you care about destination, which is going to be overwrite anyway
                        continue
                # if len(insn.operands) == 1:
                #     i = insn.operands[0]
                # else:
                #     i = insn.operands[1]
                    if i.type == X86_OP_REG:
                        reg = insn.reg_name(i.reg)
                        # print()
                        # print(getattr(state.regs, reg))
                        try:
                            value_set = ValueSet(use_state.solver.eval_upto(getattr(use_state.regs, reg), upto))
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
                        # if insn.reg_name(i.mem.disp) != None:
                        #     reg = insn.reg_name(i.mem.scale)
                        #     disp = use_state.solver.eval(getattr(use_state.regs, reg ))
                        # else:
                        disp =  ValueSet([i.mem.disp]) 
                        disp_expr = i.mem.disp

                        offset = index * scale + disp
                        # print( insn.reg_name(i.mem.segment), insn.reg_name(i.mem.base) )
                        if insn.reg_name(i.mem.segment) != None:
                            reg = insn.reg_name(i.mem.segment)
                        else:
                            # print("regstate", regstate.access(insn.reg_name(i.mem.base)) )
                            reg = insn.reg_name(i.mem.base)

                        try: 
                            base = ValueSet( use_state.solver.eval_upto(getattr(use_state.regs, reg ), upto))
                            base_expr = getattr(use_state.regs, reg )
                        except Exception:
                            base = ValueSet([0])
                            base_expr = 0

                        value_set = base + offset
                        # print(insn.mnemonic, value_set)

                    if not_floating_instruction(insn) and len(value_set._set.intersection(all_taint_sources)) != 0:
                        print("taint ", value_set, value_set._set.intersection(all_taint_sources) )
                        sinks.append(insn)
                        break
                        # elif i.type == 
        
            last_state = state
        else:
            last_state = None
            # a.op_str
            # print(state.memory)
    return sinks, func_sinks   