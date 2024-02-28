CLASS=S

make BT CLASS=$CLASS; mkdir bin/bt; mv bin/bt* bin/bt
make SP CLASS=$CLASS; mkdir bin/sp; mv bin/sp* bin/sp
make LU CLASS=$CLASS; mkdir bin/lu; mv bin/lu* bin/lu
make MG CLASS=$CLASS; mkdir bin/mg; mv bin/mg* bin/mg
make FT CLASS=$CLASS; mkdir bin/ft; mv bin/ft* bin/ft
make IS CLASS=$CLASS; mkdir bin/is; mv bin/is* bin/is
make CG CLASS=$CLASS; mkdir bin/cg; mv bin/cg* bin/cg
make EP CLASS=$CLASS; mkdir bin/ep; mv bin/ep* bin/ep

(cd bin/bt; mkdir work; fpvm_patch.sh -w work bt.$CLASS)
(cd bin/sp; mkdir work; fpvm_patch.sh -w work sp.$CLASS)
(cd bin/lu; mkdir work; fpvm_patch.sh -w work lu.$CLASS)
(cd bin/mg; mkdir work; fpvm_patch.sh -w work mg.$CLASS)
(cd bin/ft; mkdir work; fpvm_patch.sh -w work ft.$CLASS)
(cd bin/is; mkdir work; fpvm_patch.sh -w work is.$CLASS)
(cd bin/cg; mkdir work; fpvm_patch.sh -w work cg.$CLASS)
(cd bin/ep; mkdir work; fpvm_patch.sh -w work ep.$CLASS)
