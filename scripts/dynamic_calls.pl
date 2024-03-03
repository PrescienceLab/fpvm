#!/usr/bin/perl -w

use IPC::Open3;
use File::Basename;

$#ARGV>=1 or die "usage: dynamic_calls.pl libpat|all command\n";

$lib=shift;
$cmd=join(" ",@ARGV);
$first=$ARGV[0];

$lt = "ltrace -f -s 0";

if ($lib eq "all") {
    $pre = "";
} else {
    $lt .= " -l $lib";
    $pre = fileparse($first);
    $pre.="->";
}


local *LTOUT;


#open(TRACE,">$first.ltrace.out") or die "cannot open ltrace file\n";

my $pid = open3('<&STDIN','>&STDOUT',LTOUT,"$lt $cmd > $first.out");

$pid>0 or die "cannot $lt $cmd\n";


while (<LTOUT>) {
    # capture only calls directly from the executable
    #print TRACE;
    if (/^\[pid\s+\d+\]\s+$pre(\S+)\((.*)\)\s+=\s+\S+$/) {
	$func = $1;
	@t = split(/,/,$2); $numarg=$#t+1;
	$f{$func."_".$numarg}++;
    }
}

waitpid($pid,0);

# close(TRACE);


@fs = sort(keys %f);

map { $_=~/^(.*)_(\d+)/; print "$1\t$2\t$f{$_}\n"; } @fs;

