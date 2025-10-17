#!/usr/bin/perl -w

use File::Basename;

$script_dir = dirname(__FILE__);

$#ARGV >= 1 or die "usage: wrap_dynamic_calls_reverse.pl funclist exec [arch]\n";

$lf=shift;
$stem=shift;
$arch = shift || $ENV{'FPVM_ARCH'} || 'x64';

$preorig="__fpvm_orig_";

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

    
# Load the architecture-specific template
$template_file = "$script_dir/wrap_templates/reverse_wrapper_$arch.S.template";
if (!-f $template_file) {
    die "Architecture template not found: $template_file\n" .
        "Supported architectures should have templates in scripts/wrap_templates/\n";
}

open(TMPL,"$template_file") or die "cannot open $template_file\n";
$template = do { local $/; <TMPL> };
close(TMPL);

open(S,">$stem.S") or die "cannot open $stem.S\n";

print S "# This file is auto-generated and\n";
print S "# conforms with include/fpvm/additional_wrappers.h\n";
print S "# Architecture: $arch\n\n";

# Generate wrapper for each function by instantiating the template
foreach $func (@funcs) {
    $wrapper_code = $template;

    # Replace template variables
    $wrapper_code =~ s/\$FUNC\$/$func/g;

    print S $wrapper_code;
    print S "\n";
}

close(S);

print STDERR "Generated wrappers for " . scalar(@funcs) . " functions using $arch architecture\n";
