/*

  Part of FPVM

  Test code for floating point virtual machine

  Copyright (c) 2021 Peter A. Dinda - see LICENSE

*/

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdbool.h>
#define __GNU_SOURCE
#include <fenv.h>
#include <stdint.h>

#define NUM_THREADS 1



static const uint64_t CNAN_LOUD_DOUBLE = 0x7ff4000000000000UL;

// does show up in unistd for some reason...
int execvpe(char *, char **, char **); 

double foo(double x)
{
  return sin(x);
} 

void use(double x);



void print_binary_quad(const char *name, void *vptr) {
  return ;
  fprintf(stderr, "%s: ", name);
  uint64_t val = *(uint64_t*)vptr;
  for (int i = 0; i < 8; i++) {
    fprintf(stderr, " ");
    uint8_t byte = (val >> (8 * i));
    for (int b = 0; b < 8; b++) {
      fprintf(stderr, "%d", (byte >> b) & 1);
    }
  }
  fprintf(stderr, " (%lf)\n", *(double*)vptr);
}


void divzero() {
  volatile double x,y,z;
  
  x=99.0;
  y=0.0;
  //fprintf(stderr, "Doing divide by zero\n");
  z = x/y;
  use(z);
  //fprintf(stderr, "%.18le / %.18le = %.18le\n", x,y,z);
}

void nanny() {
  volatile double x,y,z;
  
  x=0.0;
  y=0.0;
  //  fprintf(stderr, "Doing NAN\n");
  z = x / y;

  print_binary_quad("x", &x);
  print_binary_quad("y", &y);
  print_binary_quad("z", &z);
  use(z);
  //fprintf(stderr, "%.18le / %.18le = %.18le\n", x,y,z);
}


void denorm()
{
  volatile double x,y,z;
  unsigned long val;
  // largest denormal number
  // 0 00000000000 111111...
  // all 1s 
  val =  0x000fffffffffffffULL;
  x=*(double*)&val;
  y=4.0;
  //fprintf(stderr, "Doing denorm\n");
  z = x/y;
  use(z);
  //fprintf(stderr, "%.18le / %.18le = %.18le\n", x,y,z);
}

void underflow() {
  volatile double x,y,z;
  unsigned long val;
  // smallest normal number
  // 0 00000000001 00000000000....1
  // all zero except for bit 52
  val =  0x0010000000000001ULL;
  x=*(double*)&val;
  y=x;
  //fprintf(stderr, "Doing underflow\n");
  z = x*y;
  use(z);
  //fprintf(stderr, "%.18le / %.18le = %.18le\n", x,y,z);
}

void overflow() {
  volatile double x,y,z;
  unsigned long val;
  // largest normal number
  // 0 1111111110 11111111...
  // all 1s except for bit 52 
  val =  0x7fefffffffffffffULL;
  x=*(double*)&val;
  y=4.0;
  //fprintf(stderr, "Doing overflow\n");
  z = x*y;

  print_binary_quad("x", &x);
  print_binary_quad("y", &y);
  print_binary_quad("z", &z);
  use(z);
  //  fprintf(stderr, "%.18le * %.18le = %.18le\n", x,y,z);
}  

void inexact() {
  volatile double x,y,z;
  unsigned long val;
  // largest normal number
  // 0 1111111110 11111111...
  // all 1s except for bit 52 
  val =  0x7fefffffffffffffULL;
  x=*(double*)&val;
  // normal number with smallest exponent, biggest mantissa
  // 0 00000000001 11111....
  // all 0s except for bit 52..0 
  val =  0x001fffffffffffffULL;
  y=*(double*)&val;
  //fprintf(stderr, "Doing inexact\n");
  z = x-y;

  print_binary_quad("x", &x);
  print_binary_quad("y", &y);
  print_binary_quad("z", &z);
  use(z);
  //fprintf(stderr, "%.18le - %.18le = %.18le\n", x,y,z);
}  

#define N 4
volatile double a[N], b[N];
volatile double result;


void setup_arrays() {
  int i;

  for (i=0;i<N;i++) {
    ((uint64_t*)a)[i] = ((uint64_t*)b)[i] = 0x7ff4000000000000UL;
  }
}

__attribute__((noinline)) void dot_prod() {
  int i;
  double sum=0.0; 


 
  for (i=0;i<N;i++) {
    sum += a[i] * b[i];
  }

  if (*(uint64_t*)&sum == 0x7ff4000000000000UL ) {
    //fprintf(stderr, "result is a canonical nan\n");
  } else {
    //fprintf(stderr, "result is not a canonical nan\n");
  }
  // will not work until relevant instructions are emulated
  //fprintf(stderr, "result=%lf\n", result);
}

  

volatile double _tmp;
void use(double x)
{
  _tmp += x;
}

void handler(int sig)
{
  fprintf(stderr, "Caught my own signal %d and am exiting\n",sig);
  exit(0);
}

void test_4_ops(double x, double y){
 double add = x+y;
 double sub = x-y;
 double mul = x*y;
 double div = x/y;
 // fprintf(stderr, "x: %f, y: %f\nx+y=%f\nx-y=%f\nx*y=%f\nx/y=%f\n", x, y, add, sub, mul, div);
 return;
}

void test_compare(double x, double y){
 bool l = x<y;
 bool g = x>y;
 bool leq = x<=y;
 bool geq = x>=y;
 bool equal = x==y;
 // fprintf(stderr, "x: %f, y: %f\nx<y=%d\nx>y=%d\nx<=y=%d\nx>=y=%d\nx==y=%d\n", x, y, l,g, leq, geq, equal);
 return;
}

void test_cast(double x, float y){
 float d_to_f = (float) x;
 int d_to_i = (int) x;
 double f_to_d = (double) y;
 //fprintf(stderr, "x (double): %f, y (float): %f\n(float) x=%f\n(int) x=%d\n(double) y =%f\n", x, y, d_to_f,d_to_i, f_to_d);
 return;
}

int do_work()
{
#if 1
 // divzero();
 // nanny();
 // denorm();

  inexact();

   return 0;


  // if we abort here, we should have some partial output in the logs
  
  if (getenv("TEST_FPE_BREAK_GENERAL_SIGNAL")) {
    signal(SIGUSR1,handler);
  }
  if (getenv("TEST_FPE_BREAK_FPE_SIGNAL")) {
    signal(SIGFPE,handler);
  }
  if (getenv("TEST_FPE_BREAK_FE_FUNC")) {
    feclearexcept(FE_ALL_EXCEPT);
  }

  underflow();
  overflow();
  inexact();

#else

  //inexact();

  //  nanny();

  /*setup_arrays();
  fprintf(stderr, "doing dot product\n");
  dot_prod();
  fprintf(stderr, "did dot product\n");*/
volatile double a, b;
 a = *(double*)&CNAN_LOUD_DOUBLE;
b = 5.0;
 //test_4_ops(a, b);
test_compare(a,b);
test_cast(a,b);
#endif

  return 0;
}



void *thread_start(void *tid)
{
  fprintf(stderr, "Running tests in spawned thread %d\n",(int)(long)tid);
  do_work();
  return 0;
}



int main(int argc, char *argv[], char *envp[])
{
  int pid;
  pthread_t tid[NUM_THREADS];
  int rc;
  int am_child = argc>1 && !strcasecmp(argv[1],"child");
  int i;
  
  if (am_child) {
    fprintf(stderr, "Forked/execed child running tests\n"); fflush(stdout);
    do_work();
    return 0;
  }

  fprintf(stderr, "Hello from test_fpvm\n");
  fprintf(stderr, "Running tests in normal mode\n");

  do_work();
  return 0;

  // while(1) {
  //   do_work();
  // }
  #define sign(x) ( x>0 ? 1 : -1 )
  #define nint(x) ( (long long) (x+0.5*sign(x)))

  volatile double y = 3085700000000000000.0;
  volatile double x = pow(y, 3.0);
  fprintf(stderr, " nint of x %d ori x %lf \n", nint(x), x);
  // x =-4.242;
  // fprintf(stderr, " nint of x %d ori x %lf \n", nint(x), x);
  // x = -4.732;
  // fprintf(stderr, " nint of x %d ori x %lf \n", nint(x), x);
  // x = 4.756;
  // fprintf(stderr, " nint of x %d ori x %lf \n", nint(x), x);
  

  return 0;
  
  fprintf(stderr, "Forking child to run tests\n");
  pid = fork();
  if (pid<0) {
    perror("fork failed");
    return -1;
  } else if (pid==0) {
    // child
    fprintf(stderr, "Running tests in forked child\n"); fflush(stdout);
    do_work();
    return 0;
  } else { // pid>0 => parent
    do {
      if (waitpid(pid,&rc,0)<0) {
	perror("wait failed");
	return -1;
      }
    } while (!WIFEXITED(rc)); // we only care about signals it caught, just an exit
    fprintf(stderr, "forked child done.\n");
  }

  fprintf(stderr, "Forking/execing child to run tests\n"); fflush(stdout);
  pid = fork();
  if (pid<0) {
    perror("fork failed");
    return -1;
  } else if (pid==0) {
    // child
    char *argv_child[] = { argv[0], "child", 0 };
    execvpe(argv_child[0],argv_child,envp);  // pass environment to child
    perror("exec failed...");
    return -1;
  } else { // pid>0 => parent
    do {
      if (waitpid(pid,&rc,0)<0) {
	perror("wait failed");
	return -1;
      }
    } while (!WIFEXITED(rc)); // we only care about signals it caught, just an exit
    if (WEXITSTATUS(rc)) {
      fprintf(stderr, "forked child failed (rc=%d)\n", WEXITSTATUS(rc));
      return -1;
    }
    fprintf(stderr, "forked child with exec done.\n");
  }

  fprintf(stderr, "Spawning %d threads to run tests\n", NUM_THREADS); fflush(stdout);
  for (i=0;i<NUM_THREADS;i++) {
    if (pthread_create(&tid[i],0,thread_start,(void*)(long)i)) {
      perror("thread creation failed");
      return -1;
    }
  }
  
  for (i=0;i<NUM_THREADS;i++) {
    pthread_join(tid[i],0);
    fprintf(stderr, "Joined thread %d\n", i);
  }

  fprintf(stderr, "Goodbye from test_fpvm\n");
  return 0;
}
  


