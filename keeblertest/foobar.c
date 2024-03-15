#include <stdio.h>

double foobar(double x, double y)
{
  printf("foobar(%lf,%lf)=%lf\n",x,y,x+y);
  return x+y;
}
