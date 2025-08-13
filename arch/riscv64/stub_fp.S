#
# void fpvm_test_instr(struct xmm *ptr) 
#  ptr = %rdi
#
.global fpvm_test_instr
fpvm_test_instr:
   // TODO:
.global my_instruction
my_instruction:
	feq.d                a4, fa5, fs0
	// TODO:
   //fsub.d f1, f2, f3
   ret



