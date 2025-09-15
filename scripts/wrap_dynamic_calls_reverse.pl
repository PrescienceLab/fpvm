#!/usr/bin/perl -w                                                                             

$#ARGV==1 or die "usage: wrap_dynamic_calls_reverse.pl funclist exec\n";

$lf=shift;
$stem=shift;

$preorig="__fpvm_orig_";


$entry = "*__fpvm_foreign_entry\@GOTPCREL(%rip)";
$exit = "*__fpvm_foreign_exit\@GOTPCREL(%rip)";

open(L,"$lf") or die "cannot open $lf\n";
while (<L>) {
    chomp();
    next if (/^\s*#/ || /^\s*$/); # kill comments and empty lines
    ($f) = split(/\s+/); $fs{$f}=1; }
close(L);
@funcs = sort keys %fs;

open(I,">$stem.inc") or die "cannot open $stem.inc\n";

print I "// This file is auto-generated and\n";
print I "// conforms with $stem.S\n";
print I "// conforms with $stem.h\n\n";

# the I file in intended to be #included only in fpvm
foreach $func (@funcs) {
    print I "void (*$preorig$func)() = 0;\n";
}
print I "\n";

print I "int fpvm_setup_additional_wrappers(void) { int rc=0;\n";
foreach $func (@funcs) {
    print I <<ENDI
  if (!($preorig$func = dlsym(RTLD_NEXT,"$func"))) {
    DEBUG("failed to setup SHIM for additional wrapper $func - ignoring\\n");
    rc=-1;
  } else {
    DEBUG("additional wrapper for $func (%p) set up\\n",$preorig$func);
  }
ENDI
;
}
print I "  if (rc) { ERROR(\"some additional wrappers not set up\\n\");\n }\n";
print I "  return rc; \n}\n\n";

close(I);

open(H,">$stem.h") or die "cannot open $stem.h\n";

print H "// This file is auto-generated and\n";
print H "// conforms with $stem.inc\n";
print H "// conforms with $stem.S\n\n";
print H "// This is intentionally blank since reverse wrappers are in use\n";
print H "\n";

close(H);

    

open(S,">$stem.S") or die "cannot open $stem.S\n";

print S "# This file is auto-generated and\n";
print S "# conforms with include/fpvm/additional_wrappers.h\n\n";

#                                                                                             
#       rdi, rsi, rdx, rcx, r8, r9, xmm0..xmm7 => rax or rdx::rax or xmm0::xmm1
#          for varargs, rax is INPUT as well, passing number
#          of vector registers used
#       scratch: rax, r10, r11  (rax, r11 safest, r10 
#       mxcsr partially preserved across boundary
#          control => callee-save
#          status  => caller-save (not preserved)
#                                                                                             
#     
#
#
# https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
#
# The wrapper function does the following steps:
#
# 1. save integer argument registers (including rax)
# 2. allocate space for mxcsr restore
# 3. stack align for call
#    call site rsp must be 16 (or 32) aligned
#    so that at entry to function, we are off by 8 (ret addr)
# 4. invoke runtime for demotion of machine xmms
#       RT code must not use SSE
#       RT returns mxcsr to use on exit
# 5. stash mxcsr for return
# 6. restore integer argument registers, including rax
# 7. invoke original function (must have alignment right)
# 8. load mxcsr from stash
# 9. unwind and return
#
#
# Planned stack frame:
#
# ret                     (-0)
# rbp stash        <= rbp (-8)   ** OK
# mxcsr_stash (8)         (-16)
# rax                     (-24)
# rdi                     (-32)
# rsi                     (-40)
# rdx                     (-48)
# rcx                     (-56)
# r8                      (-64)
# r9                      (-72)
# <blank*1>               (-80)  ** OK, caller at -80 (16*5)
# <blank*10>             (-160)  ** OK, caller at -160 (32*5) [maybe]
#
#
# 
foreach $func (@funcs) {

    print S <<ENDS

.weak $func
.globl $func\$fpvm
$func\$fpvm:
  pushq %rbp            # temporary new stack frame
  mov %rsp, %rbp        # with rbp so we can easily reference

  pushq %rax            # number of vector registers used in call
  pushq %rdi            # 1st arg
  pushq %rsi            # 2nd arg
  pushq %rdx            # 3rd arg
  pushq %rcx            # 4th arg
  pushq %r8             # 5th arg
  pushq %r9             # 6th arg
  pushq %r11            # Enforce alignment of stack

# r11 is a temporary reg not saved
# note that rbx, r12,r13,r14,r15 are callee save, but we will not use them
# r15 is GOT base pointer (optionally)
# xmm0 is 1st float arg and return
# xmm1 is 2nd float arg and return	
# xmm2..7 are 3rd through 8th float args

# invoke foreign_entry(addr_of_ret,addr_of_tramp,addr_of_func)
# this will
#  - demote argument registers
#  - configure mxcsr and other FPVM state appropriately
#  - stash state as needed
#  - switch return address to tramp address
#  - update return addressupdate the return address to the tramp address

# Create a struct arch_fpregs on the stack and stash our floating point state

  subq \$(16*16), %rsp // Allocate space for the floating point registers
  movsd %xmm0,  0x00(%rsp)
  movsd %xmm1,  0x10(%rsp)
  movsd %xmm2,  0x20(%rsp)
  movsd %xmm3,  0x30(%rsp)
  movsd %xmm4,  0x40(%rsp)
  movsd %xmm5,  0x50(%rsp)
  movsd %xmm6,  0x60(%rsp)
  movsd %xmm7,  0x70(%rsp)
  movsd %xmm8,  0x80(%rsp)
  movsd %xmm9,  0x90(%rsp)
  movsd %xmm10, 0xA0(%rsp)
  movsd %xmm11, 0xB0(%rsp)
  movsd %xmm12, 0xC0(%rsp)
  movsd %xmm13, 0xD0(%rsp)
  movsd %xmm14, 0xE0(%rsp)
  movsd %xmm15, 0xF0(%rsp)
  movq %rsp, %rcx # Pass a pointer to our floating point registers on the stack
  movq \$(16*16), %r8 # Pass the byte size of our floating point registers
                     # Probably a better (static) way to do this.

  leaq 8(%rbp), %rdi
  movq .tramp$func\@GOTPCREL(%rip), %rsi
  movq $func\@GOTPCREL(%rip), %rdx # for debugging
  call $entry

  movsd 0x00(%rsp), %xmm0
  movsd 0x10(%rsp), %xmm1
  movsd 0x20(%rsp), %xmm2
  movsd 0x30(%rsp), %xmm3
  movsd 0x40(%rsp), %xmm4
  movsd 0x50(%rsp), %xmm5
  movsd 0x60(%rsp), %xmm6
  movsd 0x70(%rsp), %xmm7
  movsd 0x80(%rsp), %xmm8
  movsd 0x90(%rsp), %xmm9
  movsd 0xA0(%rsp), %xmm10
  movsd 0xB0(%rsp), %xmm11
  movsd 0xC0(%rsp), %xmm12
  movsd 0xD0(%rsp), %xmm13
  movsd 0xE0(%rsp), %xmm14
  movsd 0xF0(%rsp), %xmm15
  addq \$(16*16), %rsp

  popq  %r11 # undo alignment
  popq  %r9
  popq  %r8
  popq  %rcx
  popq  %rdx
  popq  %rsi
  popq  %rdi
  popq  %rax

  # Tear down the frame
  popq %rbp

  # Simply jump (tail-call) to the 'real' func
  jmp $func

# for testing
#  jmp __fpvm_f_debug;
	
# the original function  will return here...
.tramp$func:
  pushq \$0         # The return address (alignment)
  movq %rsp, %rdi  # Point to the ret addr slot
  pushq %rbp       # make a frame
  mov %rsp, %rbp

  pushq %rax
  pushq %rdi
  pushq %rsi
  pushq %rdx
  pushq %rcx
  pushq %r8
  pushq %r9
  pushq %r11 # Enforce alignment

  // TODO: Save floating point state if we expect any FPRS are callee saved

#
# invoke foreign_exit(addr_of_ret)
#  
# This will update the FP state (e.g., mxcsr)
# and modify the return address back to the original
# which was captured earlier
#
  leaq 8(%rbp), %rdi
  call $exit

  popq  %r11 # undo alignment
  popq  %r9
  popq  %r8
  popq  %rcx
  popq  %rdx
  popq  %rsi
  popq  %rdi
  popq  %rax

# Calgon, take us away (back to the original caller)

  popq %rbp        # tear down frame
  ret
	
	
ENDS
;
}

close(S);
