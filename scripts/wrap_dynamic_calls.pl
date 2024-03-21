#!/usr/bin/perl -w                                                                             

$#ARGV==1 or die "usage: wrap_dynamic_calls.pl funclist stem\n";

defined($ENV{FPVM_WRAP}) or die "Please set FPVM_WRAP to either forward or reverse\n";

if ($ENV{FPVM_WRAP} eq "forward") { 
    $script = "wrap_dynamic_calls_forward.pl";
    print "generating forward wrappers\n";
} elsif ($ENV{FPVM_WRAP} eq "reverse") {
    $script = "wrap_dynamic_calls_reverse.pl";
    print "generating reverse wrappers\n";
} else {
    die "Please set FPVM_WRAP to either forward or reverse\n";
}

$lf=shift;
$stem=shift;

system "$script $lf $stem";
