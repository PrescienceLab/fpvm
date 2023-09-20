from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from regs import XMM

def sink_interest(insn):
    ans = False

    if 'mov' not in insn.mnemonic:
        return False
    
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

def source_interest(insn):
    if len(insn.operands) < 2:
        return None, None
    
    dst = insn.operands[0]
    src = insn.operands[1]
    
    ret = (None, None)
    for idx, op in enumerate([dst, src]):
        
        #only mark store of xmm as taint source
        if op.type ==  X86_OP_REG:
            if 'xmm' in insn.reg_name(op.reg):
                if idx == 0:
                    ret = (None, None)
                    break
                                #taint_source; 
                source_key = insn.reg_name(op.reg) #source key is name of xmm
                if ret[0] is None:
                    ret = (source_key, 1-idx) # idx must be 1, which is src, we want addr of dst, hence 1-idx
                else:
                    ret = (None, None)
    return ret
    
def wrap(reg):
    return '_'+reg



class TaintState:
    def __init__(self):
        for i in range(XMM.len):
            name = "xmm"+str(i)
            setattr(self, name, set())
    
    def flatten(self, remove=set([0])):
        final = set()
        for i in range(XMM.len):
            name = "xmm"+str(i)
            final |= getattr(self, name)
        # arr = np.array(list(final))    
        # final = set(arr[arr > 0x4000000].tolist())
        final = set([ele for ele in final if ele > 0x4000000])
        # print('flatten [{}]'.format(', '.join(hex(x) for x in (final-remove))))
        # print("flatten", final-remove)
        return final-remove
        
    def _to_hex(self, name):

       return set([ hex(i) for i in getattr(self, name) ])    
    def __str__(self):
        _str = []
        for i in range(XMM.len):
            name = "xmm"+str(i)
            _str.append("%s: %s" % (name, self._to_hex(name)))
        return "\n".join(_str)


class CallStack:
    def __init__(self, _tuple):
        self.func_addr = _tuple[1]
        self.call_site_addr = _tuple[0]



def taint_functions(proj, sorted_nodes, extern_functions, taint_whole_escape_functions):
    func_sinks = dict()
    #gather functions
    funcs = []
    for key, func in proj.kb.functions.items():
        if len(func.block_addrs_set) > 0:
            # print("func, ", hex(func.addr))
            funcs.append( (func.addr, max(list( func.block_addrs_set))))
        else:
            pass
            print("no blocks ", hex(func.addr))

    taint_func = set()
    extern_func = []
    for askey, blockid in sorted_nodes:
        print(hex(blockid.addr))
        assert len(blockid.callsite_tuples) >= 2
        callstack = CallStack(blockid.callsite_tuples[-2:])
        if extern_functions.isextern(blockid.addr):
            if callstack.func_addr in taint_whole_escape_functions:
                print("skip taint whole", callstack.func_addr)
                continue
            call_site = callstack.call_site_addr
            extern_func.append(callstack.func_addr)

    for askey, blockid in sorted_nodes:
        
        block = proj.factory.block(blockid.addr)
        insns = block.disassembly.insns #extract the only insn from block
        if len(insns) == 0:
            continue
        else:
            insn = insns[0]

        if insn.mnemonic == 'call' or 'j' in insn.mnemonic : #capture any kinds of jump/calls
            if insn.operands[0].type == X86_OP_IMM:
                call_to = insn.operands[0].imm
                if call_to in extern_func:
                    callstack = CallStack(blockid.callsite_tuples[-2:])
                    taint_func.add(callstack.func_addr)

    print("taint_func", [ hex(addr) for addr in taint_func ])
    return taint_func, extern_func