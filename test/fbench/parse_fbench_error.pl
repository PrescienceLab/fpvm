#!/usr/bin/perl -w

$#ARGV==0 or die "usage: parse_fbench_error.pl raw|table|summary < fbench.out\n";

$out = shift;

# errors in lines 1..8

$state=0;  # 0=await error, 1=expected, 2=received

$line=-1;

while ($l=<STDIN>) {
    chomp($l);
    if ($state==0) {
	if ($l=~/^Error.*on\s+line\s+(\d+).*$/) {
	    $line=$1;
	    $state=1;
	}
	next;
    } elsif ($state==1) {
	if ($l=~/^Expected:\s+\"\s*(.*)\"$/) {
	    $parse{$line}{"rawexpect"}=$1;
	    ($bench,@nums)=parse_bench($1);
	    $parse{$line}{"name"}=$bench;
	    push @{$parse{$line}{"expect"}}, @nums;
	    $state=2;
	}
	next;
    } elsif ($state==2) {
	if ($l=~/^Received:\s+\"\s*(.*)\"$/) {
	    $parse{$line}{"rawgot"}=$1;
	    ($bench,@nums)=parse_bench($1);
	    push @{$parse{$line}{"got"}}, @nums;
	    $state=0;
	}
	next;
    }
}

my @expect;
my @got;

if ($out eq "raw") {
    for ($line=1;$line<9;$line++) {
	if (!defined($parse{$line})) {
	    print join("\t",$line,"no error"),"\n";
	} else {
	    print join("\t", $line,$parse{$line}{"rawexpect"},$parse{$line}{"rawgot"}),"\n";
	}
    }
} elsif ($out eq "table" || $out eq "summary") {
    for ($line=1;$line<9;$line++) {
	if (!defined($parse{$line})) {
	    if ($out eq "table") {
		print join("\t",$line,"noname","0"),"\n";
	    }
	    # make sure we account for the number
	    push @expect,0;
	    push @got,0;
	} else {
	    if ($out eq "table") {
		print join("\t",$line,$parse{$line}{"name"}, euclid($parse{$line}{"expect"},$parse{$line}{"got"})),"\n";
	    }
	    push @expect, @{$parse{$line}{"expect"}};
	    push @got, @{$parse{$line}{"got"}}
	}
    }
    print euclid(\@expect,\@got),"\n";
} else {
    print "$out unknown\n";
}

sub euclid {
    my ($lhs, $rhs)=@_;
    my $s2=0;
    my $i;
    
    for ($i=0;$i<=$#{$lhs};$i++) {
	$s2 += ($lhs->[$i] - $rhs->[$i])**2;
    }

    return sqrt($s2);
}


sub parse_bench {
    my $in = shift;
    my @a = split(/\s+/,$in);
    my $name="";
    my @num;

    foreach my $part (@a) {
	my $c = substr($part,0,1);
	if ($c =~ /[\d|\+|\-|\.]/ || $part eq "inf" || $part eq "nan") {
	    push @num, $part;
	} else {
	    $name.=$part;
	}
    }

    $name=~s/\:$//;    
    return ($name,@num);
}
