#
# void fpvm_test_instr(struct xmm *ptr) 
#  ptr = %rdi
#
.global fpvm_test_instr
fpvm_test_instr:
   movupd 0x00(%rdi), %xmm0
   movupd 0x10(%rdi), %xmm1
   movupd 0x20(%rdi), %xmm2
   movupd 0x30(%rdi), %xmm3
   movupd 0x40(%rdi), %xmm4
   movupd 0x50(%rdi), %xmm5
   movupd 0x60(%rdi), %xmm6
   movupd 0x70(%rdi), %xmm7
   movupd 0x80(%rdi), %xmm8
   movupd 0x90(%rdi), %xmm9
   movupd 0xa0(%rdi), %xmm10
   movupd 0xb0(%rdi), %xmm11
   movupd 0xc0(%rdi), %xmm12
   movupd 0xd0(%rdi), %xmm13
   movupd 0xe0(%rdi), %xmm14
   movupd 0xf0(%rdi), %xmm15
.global my_instruction
my_instruction:
//   PATCHHERE
    addpd (%rsp), %xmm1
//  addsd %xmm2, %xmm1	
//  comisd %xmm2, %xmm1
//  cmpltsd %xmm2, %xmm1
//   vfmaddsd %xmm1, %xmm2, %xmm3, %xmm4
//   vfmadd132sd %xmm1, %xmm2, %xmm3
//    sqrtpd %xmm2, %xmm3
//    maxsd %xmm2, %xmm3
//    subpd %xmm2, %xmm3
//    mulpd %xmm2, %xmm3
   movupd %xmm0, 0x00(%rdi)
   movupd %xmm1, 0x10(%rdi)
   movupd %xmm2, 0x20(%rdi)
   movupd %xmm3, 0x30(%rdi)
   movupd %xmm4, 0x40(%rdi)
   movupd %xmm5, 0x50(%rdi)
   movupd %xmm6, 0x60(%rdi)
   movupd %xmm7, 0x70(%rdi)
   movupd %xmm8, 0x80(%rdi)
   movupd %xmm9, 0x90(%rdi)
   movupd %xmm10, 0xa0(%rdi)
   movupd %xmm11, 0xb0(%rdi)
   movupd %xmm12, 0xc0(%rdi)
   movupd %xmm13, 0xd0(%rdi)
   movupd %xmm14, 0xe0(%rdi)
   movupd %xmm15, 0xf0(%rdi)

   retq



