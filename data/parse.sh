input_dict=$1
output="mpfr_200_debug"
file="${input_dict}/${output}"
echo $file

grep "garbage collector :" $file > ${input_dict}/gc
grep "decode cache :" $file > ${input_dict}/dcache
grep "decoder :" $file > ${input_dict}/decoder
grep "bind :" $file > ${input_dict}/bind
grep "emulate :" $file > ${input_dict}/emulate
grep "patched trap :" $file > ${input_dict}/patch

