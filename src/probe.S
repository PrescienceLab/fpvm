.global fpvm_memaddr_probe_readable_long
fpvm_memaddr_probe_readable_long:
	movq (%rdi), %rax	#  0: 3 bytes
retgood:
	movq $1, %rax           #  3: 7 bytes
	retq                    #  a: 1 byte
retbad:
	movq $0, %rax		#  b: 7 bytes
	retq			# 12: 1 byte
	
