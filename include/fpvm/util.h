#ifndef _UTIL_
#define _UTIL_

void fpvm_dump_xmms_double(FILE *out, void *xmm);
void fpvm_dump_xmms_float(FILE *out, void *xmm);
void fpvm_dump_float_control(FILE *out, ucontext_t *uc);
void fpvm_dump_gprs(FILE *out, ucontext_t *uc);

#endif
