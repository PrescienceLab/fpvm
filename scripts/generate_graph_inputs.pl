#!/usr/bin/perl -w

if ($#ARGV!=6) {
    print "usage: generate_graph_inputs.pl benchmark factors hw2kern kern2user callwrap baseline fpvm\n";
    print <<ENDL
  benchmark    - name of benchmark
  factors      - string giving the factor combination
  hw2kern      - time in cycles for exception/trap to kernel
  kern2user    - time in cycles for kernel to user
  callwrap     - time in cycles for call wrapper overhead 
                 (foreign call, magic trap)
  baseline     - output from fpvm_time.sh of original program
  fpvm         - output from fpvm_run.sh of patched program

You will see the following files.   All files start with
a #-delimited comment that describes the columns.  The files
are in tab-delimited column, newline-delimited row format.

benchmark.factors.timing.txt
   a view of the overall execution time slowdowns and how 
   they decompose into user, sys, and realtime

benchmark.factors.amortcount.txt
   a breakdown of the number of different events per emulated instruction
   produced if telemetry is available (telemetry must be available)

benchmark.factors.amortcost.txt
   a breakdown of the number of cycles spent on different events
   per emulated instruction
   produced if telemetry and perf data is available

The above three files are intended to be concatenatable to be
able to produce data for charts showing multiple benchmarks.

benchmark.factors.tracerank.txt
   rank-popularity graph data for instruction sequence length
   produced if trace data is available

benchmark.factors.tracehist.txt
   histogram of instruction sequence length
   produced if trace data is available

ENDL
;
    exit -1;
}

$benchmark=shift;
$factors=shift;
$hw_to_kernel=shift;
$kernel_to_user=shift;
$call_wrap=shift;
$baseout=shift;
$out=shift;

$stem = "$benchmark.$factors";
$timing = "$stem.timing.txt";
$amortcost = "$stem.amortcost.txt";  
$amortcount = "$stem.amortcount.txt";  
$tracehist = "$stem.tracehist.txt";
$tracerank = "$stem.tracerank.txt";

my $have_timing=0;
my $have_telem=0;
my $have_perf=0;
my $have_trace=0;

(-e $out) or die "cannot find $out\n";

# must have timing
open(B,$baseout) or die "cannot open $baseout\n";
@basedata=<B>; print STDERR "Loaded ".($#basedata+1)." base data lines\n";
close(B);
open(O,$out) or die "cannot open $out\n";
@data=<O>; print STDERR "Loaded ".($#data+1)." fpvm data lines\n";
close(O);


%time_base = get_timing(\@basedata);
%time_fpvm = get_timing(\@data);
$have_timing = 1;

open(G,">$timing") or die "cannot open $timing\n";
print G "".join("\t","benchmark", "factors", "base_real","base_user","base_sys","base_sum","fpvm_real","fpvm_user","fpvm_sys","fpvm_sum","slowdown_real","slowdown_user","slowdown_sys", "slowdown_sum")."\n";
print G join("\t", $benchmark, $factors, $time_base{real}, $time_base{user}, $time_base{sys},$time_base{sum},$time_fpvm{real},$time_fpvm{user},$time_fpvm{sys},$time_fpvm{sum},div_clamp($time_fpvm{real},$time_base{real}),div_clamp($time_fpvm{user},$time_base{user}),div_clamp($time_fpvm{sys},$time_base{sys}),div_clamp($time_fpvm{sum},$time_base{sum})),"\n";
close(G);

print STDERR "Generating overall timing comparison in $timing\n";

%tel_fpvm = get_telemetry(\@data);
$have_telem=1;

if ($have_telem) {
    print STDERR "Found telemetry data\n";
    #print STDERR join("\n",map { " $_ => $tel_fpvm{$_}" } keys %tel_fpvm),"\n";
}

if ($have_telem) {
    print STDERR "Generating overall amortized counts in $amortcount\n";
    open(G,">$amortcount") or die "cannot open $amortcount\n";
    print G "".join("\t","benchmark", "factors", "fptraps", "promotions", "clobbers", "demotions", "correctnesstraps", "foreigncalls", "correctnessdemotions"),"\n";
    $numinst=$tel_fpvm{instructionsemulated};
    $numusefulinst=$tel_fpvm{usefulinstructionsemulated};
    $numextraneousinst=$tel_fpvm{extraneousinstructionsemulated};
    print G join("\t",
		 $benchmark,
		 $factors,
		 div_clamp($tel_fpvm{fptraps},$numusefulinst),
		 div_clamp($tel_fpvm{promotions},$numusefulinst),
		 div_clamp($tel_fpvm{clobbers},$numusefulinst),
		 div_clamp($tel_fpvm{demotions},$numusefulinst),
		 div_clamp($tel_fpvm{correctnesstraps},$numusefulinst),
		 div_clamp($tel_fpvm{correctnessforeigncalls},$numusefulinst),
		 div_clamp($tel_fpvm{correctnessdemotions},$numusefulinst)
	), "\n";
    close(G);
}



eval { %perf_fpvm = get_performance(\@data); };
$have_perf=1 if !$@;

if ($have_perf) {
    print STDERR "Found performance data\n";
#    foreach $c (keys %perf_fpvm) {
#	print STDERR " $c:\n".join("\n",map { "  $_ => $perf_fpvm{$c}{$_}" } keys %{$perf_fpvm{$c}}),"\n";
#    }
} else {
    print STDERR "No performance data available\n";
}

if ($have_perf) {
# generate performance breakdown data
    print STDERR "Generating overall amortized costs in $amortcost\n";
    open(G,">$amortcost") or die "cannot open $amortcost\n";
    print G "".join("\t","benchmark", "factors", "hardware", "kernel", "decodecache", "decoder", "binder", "emulator", "garbage", "foreigncall", "correcttrap","total")."\n";
    print G join("\t", $benchmark, $factors)."\t";
    $numfpe=$tel_fpvm{fptraps};
    $numsinglestep=$tel_fpvm{singlesteptraps};
    $numcor=$tel_fpvm{correctnesstraps};
    $numfor=$tel_fpvm{correctnessforeigncalls};
    $numinst=$tel_fpvm{instructionsemulated};
    $numusefulinst=$tel_fpvm{usefulinstructionsemulated};
    $numextraneousinst=$tel_fpvm{extraneousinstructionsemulated};
    $hw = div_clamp($hw_to_kernel*($numfpe-$numsinglestep),$numusefulinst);
    $kern = div_clamp($kernel_to_user*($numfpe-$numsinglestep),$numusefulinst);
    $decache = div_clamp($perf_fpvm{decodecache}{sum},$numusefulinst);
    $decode = div_clamp($perf_fpvm{decoder}{sum},$numusefulinst);
    $bind = div_clamp($perf_fpvm{bind}{sum},$numusefulinst);
    $emul = div_clamp($perf_fpvm{emulate}{sum},$numusefulinst);
    $gc = div_clamp($perf_fpvm{garbagecollector}{sum},$numusefulinst);
    $fcall = div_clamp($perf_fpvm{foreigncall}{sum}+$call_wrap*$numfor,$numusefulinst);
    $corr = div_clamp($perf_fpvm{correctness}{sum}+($hw_to_kernel+$kernel_to_user)*$numcor,$numusefulinst);
    $total = $hw+$kern+$decache+$decode+$bind+$emul+$gc+$fcall+$corr;
    print G join("\t",$hw,$kern,$decache,$decode,$bind,$emul,$gc,$fcall,$corr,$total)."\n";
    close(G);
}


$have_trace = check_for_trace(\@data);

if ($have_trace) {
    print STDERR "Found trace data\n";
    print STDERR "Generating trace histogram and ranks\n";
    handle_trace(\@data,$benchmark,$factors,$tracerank,$tracehist);
}

print "Done.\n";

sub div_clamp {
    my ($a,$b)=@_;
    if ($b!=0) {
	return $a/$b;
    } else {
	return 0;
    }
}

sub get_timing {
    my ($dr)=@_;
    foreach my $l (@{$dr}) {
#	print $l if $l=~/^fpvm\s+time"/;
	if ($l=~/^fpvm\s+time:\s+real\s+(\S+)\s+user\s+(\S+)\s+sys\s+(\S+)$/) {
	    return (real => $1, user => $2, sys => $3, sum => ($2 + $3));
	}
    }
    die "cannot find timing info\n";
}


sub get_telemetry {
    my ($dr)=@_;
    my %h;
    foreach my $l (@{$dr}) {
	if ($l=~/^fpvm\s+info\(.*\):\s+telemetry:\s+(\S.*)$/) {
	    my @pieces = split(/,/,$1);
	    foreach my $p (@pieces) {
		$p=~/\s*(\S+)\s+(\S.*)/;
		my $n = $1;
		my $field=$2;
		$field=~s/\s//g;
		$field=~s/\(.*\)//g;
		$h{$field}=$n;
	    }
	    return %h;
	}
    }
    die "cannot find telemetry\n";
}


sub get_performance {
    my ($dr)=@_;
    my %h;
    my $found=0;
    foreach my $l (@{$dr}) {
	if ($l=~/^fpvm\s+info\(.*\):\s+perf:\s+(\S.*) :\s+(\S.*)$/) {
	    my $comp=$1;
	    my @pieces = split(/\s+/,$2);
	    $comp=~s/\s+//g;
	    foreach my $p (@pieces) {
		my ($field, $val) = split(/=/,$p);
		$h{$comp}{$field}=$val;
	    }
	    # compute avg, stddev ourselves just in case
	    if ($h{$comp}{count}==0) {
		$h{$comp}{avg} = 0.0;
		$h{$comp}{std} = 0.0;
		$h{$comp}{min} = 0;
		$h{$comp}{max} = 0;
	    } else {
		$h{$comp}{avg} = $h{$comp}{sum}/$h{$comp}{count};
		$h{$comp}{std} = sqrt($h{$comp}{sum2}/$h{$comp}{count}
				      - $h{$comp}{avg}*$h{$comp}{avg});
	    }
	    $found=1;
	}
    }
    die "cannot find telemetry\n" if !$found;
    return %h;
}
    
sub check_for_trace {
    my ($dr)=@_;
    foreach my $l (@{$dr}) {
	if ($l=~/^fpvm\s+info\(.*\):\s+trace:\s+TRACE STATS BEGIN$/) {
	    return 1;
	}
    }
    return 0;
}
    
sub handle_trace {
    my ($dr, $bm, $fa, $tr, $tl) = @_;
    my $i;
    
    for ($i=0;$i<=$#{$dr};$i++) {
	last if ($dr->[$i]=~/^fpvm\s+info\(.*\):\s+trace:\s+trace rank popularity:$/);
    }
    $i++;
    open(G,">$tr") or die "cannot open $tr\n";
    print G "benchmark\tfactors\trank\tcumprob\tprob\tcount\tlength\n";
    for (;$i<=$#{$dr};$i++) {
	if ($dr->[$i]=~/rank\s+(\d+)\s+->\s+(\d+)\s\((\S+)\%\s+(\S+)\%\)\s+\[length\s+(\d+)\]/) {
	    my ($r,$n,$p,$cp,$len) = ($1,$2,$3,$4,$5);
	    print G join("\t", $bm, $fa, $r, $cp, $p, $n, $len),"\n";
	} else {
	    last;
	}
    }
    close(G);
    
    for (;$i<=$#{$dr};$i++) {
	last if ($dr->[$i]=~/^fpvm\s+info\(.*\):\s+trace:\s+trace length popularity:$/);
    }
    $i++;
    open(G,">$tl") or die "cannot open $tl\n";
    print G "benchmark\tfactors\tlength\tcumprob\tprob\tcount\n";
    for (;$i<=$#{$dr};$i++) {
	if ($dr->[$i]=~/length\s+(\d+)\s+->\s+(\d+)\s\((\S+)\%\s+(\S+)\%\)/) {
	    my ($len,$n,$p,$cp) = ($1,$2,$3,$4);
	    print G join("\t", $bm, $fa, $len, $cp, $p, $n),"\n";
	} else {
	    last;
	}
    }
    close(G);

}
