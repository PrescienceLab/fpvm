#include <stdio.h>

extern double foobar(double x, double y);

int main()
{
  double result = foobar(1.0,2.0);
  
  printf("1.0+2.0=%lf\n",result);
  
  return 0;
}
