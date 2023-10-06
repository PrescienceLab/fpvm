
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import csv

def bridge_e9patch(binary, sinks, func_sinks, file):
    
    mem_mem = []
    reg_mem = []
    mem_reg = []
    reg_reg = []
    for insn in sinks:
        src = insn.operands[1].type
        dst = insn.operands[0].type
        if src == X86_OP_MEM:
            if dst == X86_OP_MEM:
                mem_mem.append(insn.address)

            elif dst == X86_OP_REG:
                mem_reg.append(insn.address)

        if src == X86_OP_REG:
            if dst == X86_OP_MEM:
                reg_mem.append(insn.address)
            
            elif dst == X86_OP_REG:
                reg_reg.append(insn.address)
    
    
    with open(f'{binary}_call_patches.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for addr in func_sinks.keys():
            writer.writerow([int(hex(addr), base=16)])
    
    with open(f'{binary}_mem_patches.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for addr in set(mem_reg):
            writer.writerow([int(hex(addr), base=16)])
    

    with open(file, 'w') as file:
        # file.write(f"memaddr={','.join( hex(addr) for addr in set(mem_reg))}")
        # file.write('\n')
        # file.write(f"calladdr={','.join( hex(addr) for addr in func_sinks.keys())}")
        # file.write('\n')
        file.write("e9tool ")
        file.write(f"-M \"addr={binary}_call_patches[0]\" -P \'before trap\' ")
        file.write(f"-M \"addr={binary}_mem_patches[0]\" -P \'before trap\' ")
        file.write(binary)
        file.write('\n')
