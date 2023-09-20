with open('post.file', 'r') as f:
    lines = f.readlines()
    lines = [line.rstrip() for line in lines]
    call_addr = set()
    func_list = set()
# ftruncate
    exclude_list = ['_Znam', '_Znwm', '_ZdlPv', '_ZdaPv', 'free', 'malloc', 'memcpy', 'memmove',\
         'atoi', 'getpid',  \
         '__stack_chk_fail', '__cxa_allocate_exception', '__cxa_throw', '__cxa_guard_acquire',\
        'strstr', 'strcspn', 'strncmp', 'strncpy', 'strcpy', 'strtok', 'strcmp', 'strcat',\
         'pow', 'log', 'log10', 'sqrt', '__powidf2', 'ldexp',\
             'exp', 'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh', 'asinh', 'acosh', 'atanh', 'atan2', \
             'ceil', 'floor', 'round', 'lround']

    exclude_expr = ['H5', "__cxa", 'MPI', 'char', '_gfortran', 'mem']
    for line in lines:
        l = line.split(' ')
        print(l)
        skip = 0
        for sub_expr in exclude_expr:
            if sub_expr in l[-1]:
                skip = 1 
                break
        if skip or l[-1] in exclude_list:
            continue
        func_list.add(l[-1])
        call_addr.add(l[2])

    func_list = set(func_list)
    print('\n'.join(func_list))
    print("retain portion", len(call_addr)/len(lines))

    with open("all_printf", 'r') as f:
        lines = f.readlines()
        lines = [line.rstrip() for line in lines]
        for line in lines:
            line = '0x'+line[2:]
            print(line)
            call_addr.add(line)

    binary = 'enzo.exe'
    file = 'enzo-patch-post'
    
    import csv
    
    with open('call_patches.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for addr in call_addr:
            writer.writerow([int(addr, base=16)])

    
    # with open(file, 'w') as file:
    #     file.write(f"calladdr={','.join(call_addr)}")
    #     file.write('\n')
    #     file.write("e9tool -M \"addr=${calladdr}\" -P \'before trap\' ")
    #     file.write(binary)
    #     file.write('\n')
