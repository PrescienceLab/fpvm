#!/usr/bin/perl -w                                                                             

$#ARGV==1 or die "usage: wrap_dynamic_calls.pl funclist stem\n";


$lf=shift;
$stem=shift;

system "wrap_dynamic_calls_forward.pl $lf $stem";
