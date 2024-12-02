.global dumpregs
dumpregs:
	vmovapd %xmm0,0x0(%rdi)
	vmovapd %xmm1,0x10(%rdi)
	vmovapd %xmm2,0x20(%rdi)
	vmovapd %xmm3,0x30(%rdi)
	vmovapd %xmm4,0x40(%rdi)
	vmovapd %xmm5,0x50(%rdi)
	vmovapd %xmm6,0x60(%rdi)
	vmovapd %xmm7,0x70(%rdi)
	vmovapd %xmm8,0x80(%rdi)
	vmovapd %xmm9,0x90(%rdi)
	vmovapd %xmm10,0xa0(%rdi)
	vmovapd %xmm11,0xb0(%rdi)
	vmovapd %xmm12,0xc0(%rdi)
	vmovapd %xmm13,0xd0(%rdi)
	vmovapd %xmm14,0xe0(%rdi)
	vmovapd %xmm15,0xf0(%rdi)
	ret
