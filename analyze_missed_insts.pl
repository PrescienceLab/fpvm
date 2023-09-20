#!/usr/bin/perl -w

while (<STDIN>) {
    if (/-\s+instr\s+(.*)\s+-/) {
	$inst = $1;
#	print $inst,"\n";
	push @insts, $inst;
	($opcode) = split(/\s+/,$inst);
	$insts{$inst}++;
	$ops{$opcode}++;

    }
}

@oplist = sort { $ops{$b} <=> $ops{$a} } keys %ops;
@instlist = sort { $insts{$b} <=> $insts{$a} } keys %insts;

print "\nOpcodes by popularity\n\n";
map { print $ops{$_}."\t".$_."\n" } @oplist;
print "\nWhole instructions by popularity\n\n";
map { print $insts{$_}."\t".$_."\n" } @instlist;

