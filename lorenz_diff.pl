#!/usr/bin/perl -w

$#ARGV==1 or die "usage: lorenz_diff 1st 2nd\n";

$f1=shift;
$f2=shift;

open(F1,$f1) or die "$f1\n";
open(F2,$f2) or die "$f2\n";

while ($l1=<F1>) {
    $l2=<F2>;
    chomp($l2);
    chomp($l1);
#    print $l1." vs ".$l2;
    ($t1,$x1,$y1,$z1) = split(/\s+/,$l1);
    ($t2,$x2,$y2,$z2) = split(/\s+/,$l2);
    print join("\t",$t1,$x1-$x2,$y1-$y2,$z1-$z2),"\n";
#    last;
}
    
       
