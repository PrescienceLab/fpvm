#define _GNU_SOURCE
#include <fenv.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include "fpvm_ioctl.h"

#define N 100000

uint64_t start;
uint64_t end;

uint64_t time[N];
uint64_t count = 0;

extern void * _user_fpvm_entry;

static inline uint64_t
my_rdtsc (void)
{
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | ((uint64_t)(hi) << 32);
}

void our_handler(void *test){
    end = my_rdtsc();
    time[count++] = end;
    if (count == N){
	for (int i = 1; i < count; i++){
	    printf("%d\t%ld\n",i,time[i] - time[i-1]);
	}
	exit(0);
    }
    return;
}

int main() {
    int pid;
    int file_desc;
    // memset(time, 1, N*sizeof(uint64_t));

#if 0
    signal(SIGFPE, our_handler);
#else
    // Open
    file_desc = open("/dev/fpvm_dev", O_RDWR);

    // Try registering handler with fpvm_dev
    if (!(file_desc < 0)){
	ioctl(file_desc, FPVM_IOCTL_REG, &_user_fpvm_entry);
    }
#endif
    feclearexcept(FE_ALL_EXCEPT);
    feenableexcept(FE_ALL_EXCEPT);

    volatile double a = 0.123;
    volatile double b = 0.456;
    volatile double z = a/b;

    return 0;

}

