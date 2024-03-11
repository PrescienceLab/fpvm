#!/usr/bin/perl -w

$#ARGV==1 or die "usage: patches_to_functions.pl patchfile origexec\n";

$pf=shift;
$ex=shift;

(-e $ex) or die "$ex can't find\n";

open(PF,"$pf") or die "cannot open $pf\n";

system "objdump -d $ex > _$ex.dis";

while ($cur=<PF>) {
    # dedos
    $cur=~s/\r//g;
    chomp($cur);
    $h=sprintf("%x",$cur);
    $f = get_containing_func($ex,$h);
    $i = get_instruction($ex,$h);
    print "$cur\t$h\t$f\t$i\n";
}


sub get_instruction
{
    my ($e,$a)=@_;
    my @d = `grep $a _$ex.dis`;
    chomp($d[0]);
    return $d[0];
}

sub get_containing_func
{
    my ($e,$a)=@_;
    my @d = `addr2line -f -C -e $e 0x$a`;
    chomp($d[0]);
    return $d[0];
}
