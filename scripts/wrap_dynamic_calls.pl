#!/usr/bin/perl -w                                                                             

$#ARGV==1 or die "usage: wrap_dynamic_calls.pl funclist stem\n";

$lf=shift;
$stem=shift;

$preorig="__fpvm_orig_";


$entry = "*__fpvm_foreign_entry\@GOTPCREL(%rip)";

open(L,"$lf") or die "cannot open $lf\n";
while (<L>) {
    chomp();
    next if (/^\s*#/ || /^\s*$/); # kill comments and empty lines
    ($f) = split(/\t/); $fs{$f}=1; }
close(L);
@funcs = sort keys %fs;

open(H,">$stem.h") or die "cannot open $stem.h\n";

print H "// This file is auto-generated and\n";
print H "// conforms with src/additional_wrappers.S\n\n";

# the H file in intended to be #included only in fpvm
foreach $func (@funcs) {
    print H "void (*$preorig$func)() = 0;\n";
}
print H "\n";

print H "int fpvm_setup_additional_wrappers(void) { int rc=0;\n";
foreach $func (@funcs) {
    print H <<ENDH
  if (!($preorig$func = dlsym(RTLD_NEXT,"$func"))) {
    DEBUG("failed to setup SHIM for additional wrapper $func - ignoring\\n");
    rc=-1;
  } else {
    DEBUG("additional wrapper for $func (%p) set up\\n",$preorig$func);
  }
ENDH
;
}
print H "  if (rc) { ERROR(\"some additional wrappers not set up\\n\");\n }\n";
print H "  return rc; \n}\n\n";

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

.global $func
$func:
    pushq %rbp           # -8
    movq %rsp, %rbp    
    subq \$8, %rsp        # -16 space for mxcsr at -8(%rbp) 
    pushq %rax
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9            # odd number of pushes -> OK
    movq $func\@GOTPCREL(%rip), %rdi # for debugging
    call $entry          # returns with desired mxcsr in eax
    movl %eax, -8(%rbp)  # stash exit msr for later
    popq  %r9
    popq  %r8
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    popq  %rax           # now at even number of pushes
    subq \$8, %rsp        # now odd
    movq $preorig$func\@GOTPCREL(%rip), %r11
    call *(%r11)         # lookup func and call
    ldmxcsr -8(%rbp)     # restore mxcsr as required
    movq %rbp, %rsp      # unwind stack frame
    popq %rbp
    retq

ENDS
;
}

close(S);
