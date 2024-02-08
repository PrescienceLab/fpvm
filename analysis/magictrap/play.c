#include <stdio.h>
#include <stdint.h>

int main(void)
{
	volatile double x=99.3;
	volatile uint64_t *xp=(uint64_t*)&x;
	volatile uint64_t t;

	t = *xp;

	printf("t=%016lx\n",t);
	printf("x=%lf\n",x);
	
	return 0;


}
