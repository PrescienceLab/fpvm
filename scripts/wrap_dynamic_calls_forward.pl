#!/usr/bin/perl -w                                                                             

$#ARGV==1 or die "usage: wrap_dynamic_calls_forward.pl funclist exec\n";

$lf=shift;
$stem=shift;

$preorig="__fpvm_orig_";

$prefpvm="fpvm_";

$entry = "*__fpvm_foreign_entry\@GOTPCREL(%rip)";
$exit = "*__fpvm_foreign_exit\@GOTPCREL(%rip)";

open(L,"$lf") or die "cannot open $lf\n";
while (<L>) {
    chomp();
    next if (/^\s*#/ || /^\s*$/); # kill comments and empty lines
    ($f) = split(/\t/); $fs{$f}=1; }
close(L);
@funcs = sort keys %fs;

open(I,">$stem.inc") or die "cannot open $stem.h\n";

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
print H "// NOTE THIS ONLY WORKS WITH integral return functions!\n\n";
    
foreach $func (@funcs) {
    print H "uint64_t fpvm_$func)();\n";
}
print H "\n";

close(H);

    

open(S,">$stem.S") or die "cannot open $stem.S\n";

print S "# This file is auto-generated and\n";
print S "# conforms with include/fpvm/additional_wrappers.h\n\n";

#                                                                                             
#       rdi, rsi, rdx, rcx, r8, r9, xmm0..xmm7 => rax or rdx::rax or xmm0
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

.globl $func
$func:
  pushq %rbp
  mov %rsp, %rbp

  pushq %rax
  pushq %rdi
  pushq %rsi
  pushq %rdx
  pushq %rcx
  pushq %r8
  pushq %r9
  pushq %r11 # Enforce alignment

# invoke foreign_entry(addr_of_ret,addr_of_tramp,addr_of_func)
# this will
#  - demote argument registers
#  - configure mxcsr and other FPVM state appropriately
#  - stash state as needed
#  - switch return address to tramp address
#  - update return addressupdate the return address to the tramp address
       
  leaq 8(%rbp), %rdi
  movq .tramp$func\@GOTPCREL(%rip), %rsi
  movq $func\@GOTPCREL(%rip), %rdx # for debugging
  call $entry

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

# Invoke original function via jump through our table
# it will experience the same call stack as if this
# wrapper did not exist
  movq $preorig$func\@GOTPCREL(%rip), %r11
  jmp *(%r11)
	
# the original function  will return here...
.tramp$func:
  pushq \$0        # The return address (alignment)
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

# and a wrapper to make it easier to call from in FPVM
.globl $prefpvm$func
$prefpvm$func:
  movq $preorig$func\@GOTPCREL(%rip), %r11
  jmp *(%r11)
	
	
ENDS
;
}

close(S);
