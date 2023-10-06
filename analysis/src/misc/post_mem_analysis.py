with open('out/mem_post.file', 'r') as f:
    lines = f.readlines()
    lines = [line.rstrip() for line in lines]
   
    file = 'enzo-mem-patch-post.csv'
    import csv
    with open(file, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for line in lines:
            l = line.split(' ')
            addr = l[0]
            writer.writerow([int(addr, base=16)])

    # with open(file, 'w') as file:
    #     file.write(f"calladdr={','.join(call_addr)}")
    #     file.write('\n')
    #     file.write("e9tool -M \"addr=${calladdr}\" -P \'before trap\' ")
    #     file.write(binary)
    #     file.write('\n')
