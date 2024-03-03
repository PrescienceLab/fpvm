#!/usr/bin/perl -w                                                                             

$#ARGV==1 or die "usage: wrap_dynamic_calls.pl funclist stem\n";

$lf=shift;
$stem=shift;

$preorig="__fpvm_orig_";


$mxcsr_in="__fpvm_mxcsr_mask_entry";
$mxcsr_out="__fpvm_mxcsr_mask_exit";
$demote_regs = "fpvm_emulator_demote_machine_registers";

open(L,"$lf") or die "cannot open $lf\n";
while (<L>) { ($f) = split(/\t/); $fs{$f}=1; }
close(L);
@funcs = sort keys %fs;

open(H,">$stem.h") or die "cannot open $stem.h\n";

print S "// This file is auto-generated and\n";
print S "// conforms with src/additional_wrappers.S\n\n";

# the H file in intended to be #included only in fpvm
foreach $func (@funcs) {
    print H "void (*$preorig$func)(...) = 0;\n";
}
print H "\n";

print H "int fpvm_setup_additional_wrappers(void) { int rc=0;\n";
foreach $func (@funcs) {
    print H "  if (0!=($preorig$func = dlsym(RTLD_NEXT,\"$func\")) { DEBUG(\"failed to setup SHIM for additional wrapper %s - ignoring\\n\", \"$func\"); rc=-1; }\n";
}
print H "if (rc) { ERROR(\"some additional wrappers not set up\\n\");\n }";
print H "return rc; \n}\n\n";

close(H);

open(S,">$stem.S") or die "cannot open $stem.S\n";

print S "# This file is auto-generated and\n";
print S "# conforms with include/fpvm/additional_wrappers.h\n\n";

#                                                                                             
#                                                                                             
#                                                                                             
#                                                                                             
#                                                                                             
# This is a bit bogus since the stack will be off by 16 at                               
# entry to the wrapped function - a better way to do this                                 
# would be to have a per-thread location to stash info, and                                   
# then stash the original return address there, and modify the                                
# caller stack frame to return to us, then jump.                                              
# then on return to us, we can jump to the stashed value
foreach $func (@funcs) {
    print S ".global $func\n$func:\n";
    print S "  leaq -8(%rsp),%rsp\n";   # try to establish alignment and stash location
    print S "  stmxcsr (%rsp)\n"; # must be in an m32... 
    print S "  movl (%rsp),%r11d\n";
    print S "  orl $mxcsr_in, %r11d\n";
    print S "  movl %r11d, (%rsp)\n";
    print S "  ldmxcsr (%rsp)\n"; # turn off FP traps                                         
    print S "  call $demote_regs\n";
    print S "  movq $preorig$func, %r11\n";
    print S "  call *%r11\n";   # invoke original function
    print S "  stmxcsr (%rsp)\n"; # must be in an m32... 
    print S "  movl (%rsp),%r11d\n";
    print S "  andl $mxcsr_out, %r11d\n";
    print S "  movl %r11d, (%rsp)\n";
    print S "  ldmxcsr (%rsp)\n"; # turn on FP traps                                         
    print S "  leaq +8(%rsp),%rsp\n";  # now do not touch any unsafe register
    print S "  ret\n\n";
}

close(S);
