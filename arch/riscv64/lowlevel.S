# void riscv64_fprs_out_f(void *where_to_put_fpr_contents)
.global riscv64_fprs_out_f
riscv64_fprs_out_f:
	fsw  f0, 0x000(a0)
	fsw  f1, 0x004(a0)
	fsw  f2, 0x008(a0)
	fsw  f3, 0x00c(a0)
	fsw  f4, 0x010(a0)
	fsw  f5, 0x014(a0)
	fsw  f6, 0x018(a0)
	fsw  f7, 0x01c(a0)
	fsw  f8, 0x020(a0)
	fsw  f9, 0x024(a0)
	fsw f10, 0x028(a0)
	fsw f11, 0x02c(a0)
	fsw f12, 0x030(a0)
	fsw f13, 0x034(a0)
	fsw f14, 0x038(a0)
	fsw f15, 0x03c(a0)
	fsw f16, 0x040(a0)
	fsw f17, 0x044(a0)
	fsw f18, 0x048(a0)
	fsw f19, 0x04c(a0)
	fsw f20, 0x050(a0)
	fsw f21, 0x054(a0)
	fsw f22, 0x058(a0)
	fsw f23, 0x05c(a0)
	fsw f24, 0x060(a0)
	fsw f25, 0x064(a0)
	fsw f26, 0x068(a0)
	fsw f27, 0x06c(a0)
	fsw f28, 0x070(a0)
	fsw f29, 0x074(a0)
	fsw f30, 0x078(a0)
	fsw f31, 0x07c(a0)

	ret

# void riscv64_fprs_in_f(void *where_to_get_fpr_contents)
.global riscv64_fprs_in_f
riscv64_fprs_in_f:
	flw  f0, 0x000(a0)
	flw  f1, 0x004(a0)
	flw  f2, 0x008(a0)
	flw  f3, 0x00c(a0)
	flw  f4, 0x010(a0)
	flw  f5, 0x014(a0)
	flw  f6, 0x018(a0)
	flw  f7, 0x01c(a0)
	flw  f8, 0x020(a0)
	flw  f9, 0x024(a0)
	flw f10, 0x028(a0)
	flw f11, 0x02c(a0)
	flw f12, 0x030(a0)
	flw f13, 0x034(a0)
	flw f14, 0x038(a0)
	flw f15, 0x03c(a0)
	flw f16, 0x040(a0)
	flw f17, 0x044(a0)
	flw f18, 0x048(a0)
	flw f19, 0x04c(a0)
	flw f20, 0x050(a0)
	flw f21, 0x054(a0)
	flw f22, 0x058(a0)
	flw f23, 0x05c(a0)
	flw f24, 0x060(a0)
	flw f25, 0x064(a0)
	flw f26, 0x068(a0)
	flw f27, 0x06c(a0)
	flw f28, 0x070(a0)
	flw f29, 0x074(a0)
	flw f30, 0x078(a0)
	flw f31, 0x07c(a0)

	ret

	
# void riscv64_fprs_out_d(void *where_to_put_fpr_contents)
.global riscv64_fprs_out_d
riscv64_fprs_out_d:
	fsd  f0, 0x000(a0)
	fsd  f1, 0x008(a0)
	fsd  f2, 0x010(a0)
	fsd  f3, 0x018(a0)
	fsd  f4, 0x020(a0)
	fsd  f5, 0x028(a0)
	fsd  f6, 0x030(a0)
	fsd  f7, 0x038(a0)
	fsd  f8, 0x040(a0)
	fsd  f9, 0x048(a0)
	fsd f10, 0x050(a0)
	fsd f11, 0x058(a0)
	fsd f12, 0x060(a0)
	fsd f13, 0x068(a0)
	fsd f14, 0x070(a0)
	fsd f15, 0x078(a0)
	fsd f16, 0x080(a0)
	fsd f17, 0x088(a0)
	fsd f18, 0x090(a0)
	fsd f19, 0x098(a0)
	fsd f20, 0x0a0(a0)
	fsd f21, 0x0a8(a0)
	fsd f22, 0x0b0(a0)
	fsd f23, 0x0b8(a0)
	fsd f24, 0x0c0(a0)
	fsd f25, 0x0c8(a0)
	fsd f26, 0x0d0(a0)
	fsd f27, 0x0d8(a0)
	fsd f28, 0x0e0(a0)
	fsd f29, 0x0e8(a0)
	fsd f30, 0x0f0(a0)
	fsd f31, 0x0f8(a0)

	ret


# void riscv64_fprs_in_d(void *where_to_get_fpr_contents)
.global riscv64_fprs_in_d
riscv64_fprs_in_d:
	fld  f0, 0x000(a0)
	fld  f1, 0x008(a0)
	fld  f2, 0x010(a0)
	fld  f3, 0x018(a0)
	fld  f4, 0x020(a0)
	fld  f5, 0x028(a0)
	fld  f6, 0x030(a0)
	fld  f7, 0x038(a0)
	fld  f8, 0x040(a0)
	fld  f9, 0x048(a0)
	fld f10, 0x050(a0)
	fld f11, 0x058(a0)
	fld f12, 0x060(a0)
	fld f13, 0x068(a0)
	fld f14, 0x070(a0)
	fld f15, 0x078(a0)
	fld f16, 0x080(a0)
	fld f17, 0x088(a0)
	fld f18, 0x090(a0)
	fld f19, 0x098(a0)
	fld f20, 0x0a0(a0)
	fld f21, 0x0a8(a0)
	fld f22, 0x0b0(a0)
	fld f23, 0x0b8(a0)
	fld f24, 0x0c0(a0)
	fld f25, 0x0c8(a0)
	fld f26, 0x0d0(a0)
	fld f27, 0x0d8(a0)
	fld f28, 0x0e0(a0)
	fld f29, 0x0e8(a0)
	fld f30, 0x0f0(a0)
	fld f31, 0x0f8(a0)

	ret

// not supported on any machine yet, but here for completeness
#define NO_Q 1

#if NO_Q
	
# void riscv64_fprs_out_q(void *where_to_put_fpr_contents)
.global riscv64_fprs_out_q
riscv64_fprs_out_q:
	ret
	
# void riscv64_fprs_in_q(void *where_to_get_fpr_contents)
.global riscv64_fprs_in_q
riscv64_fprs_in_q:
	ret

#else

# void riscv64_fprs_out_q(void *where_to_put_fpr_contents)
.global riscv64_fprs_out_q
riscv64_fprs_out_q:
	fsq  f0, 0x000(a0)
	fsq  f1, 0x010(a0)
	fsq  f2, 0x020(a0)
	fsq  f3, 0x030(a0)
	fsq  f4, 0x040(a0)
	fsq  f5, 0x050(a0)
	fsq  f6, 0x060(a0)
	fsq  f7, 0x070(a0)
	fsq  f8, 0x080(a0)
	fsq  f9, 0x090(a0)
	fsq f10, 0x0a0(a0)
	fsq f11, 0x0b0(a0)
	fsq f12, 0x0c0(a0)
	fsq f13, 0x0d0(a0)
	fsq f14, 0x0e0(a0)
	fsq f15, 0x0f0(a0)
	fsq f16, 0x100(a0)
	fsq f17, 0x110(a0)
	fsq f18, 0x120(a0)
	fsq f19, 0x130(a0)
	fsq f20, 0x140(a0)
	fsq f21, 0x150(a0)
	fsq f22, 0x160(a0)
	fsq f23, 0x170(a0)
	fsq f24, 0x180(a0)
	fsq f25, 0x190(a0)
	fsq f26, 0x1a0(a0)
	fsq f27, 0x1b0(a0)
	fsq f28, 0x1c0(a0)
	fsq f29, 0x1d0(a0)
	fsq f30, 0x1e0(a0)
	fsq f31, 0x1f0(a0)

	ret

	
# void riscv64_fprs_in_q(void *where_to_get_fpr_contents)
.global riscv64_fprs_in_q
riscv64_fprs_in_q:
	flq  f0, 0x000(a0)
	flq  f1, 0x010(a0)
	flq  f2, 0x020(a0)
	flq  f3, 0x030(a0)
	flq  f4, 0x040(a0)
	flq  f5, 0x050(a0)
	flq  f6, 0x060(a0)
	flq  f7, 0x070(a0)
	flq  f8, 0x080(a0)
	flq  f9, 0x090(a0)
	flq f10, 0x0a0(a0)
	flq f11, 0x0b0(a0)
	flq f12, 0x0c0(a0)
	flq f13, 0x0d0(a0)
	flq f14, 0x0e0(a0)
	flq f15, 0x0f0(a0)
	flq f16, 0x100(a0)
	flq f17, 0x110(a0)
	flq f18, 0x120(a0)
	flq f19, 0x130(a0)
	flq f20, 0x140(a0)
	flq f21, 0x150(a0)
	flq f22, 0x160(a0)
	flq f23, 0x170(a0)
	flq f24, 0x180(a0)
	flq f25, 0x190(a0)
	flq f26, 0x1a0(a0)
	flq f27, 0x1b0(a0)
	flq f28, 0x1c0(a0)
	flq f29, 0x1d0(a0)
	flq f30, 0x1e0(a0)
	flq f31, 0x1f0(a0)

	ret
	

#endif	
