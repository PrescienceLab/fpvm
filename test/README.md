# Programs with ***NO*** FP Escapes to Memory
  * `fbench`
  * `ffbench`?
    I (KGH) am not 100% sure that this is accurate.
    This would require more investigation.
  * `double_pendulum`, so long as per-iteration-step printing is disabled.
  * `three-body`

Some programs will "escape" floating-point values to memory.
Usually, this is because of printing and/or type-casting reasons.
For example, the following C would cause an escape to the stack to reinterpret the bits from FP to integer.
```c
double my_pi = 3.14;
printf("my_pi=%lf (%ul)\n", my_pi, *(unsigned long*)&my_pi);
```

This will not always be the case for every architecture!
Most architectures have a way to move a floating-point value directly to an integer register from a floating point one.
However, we have not seen this code produced by a compiler yet, so we will leave this as a problem for later.
We have only ever seen hand-written assembly use these direct FP->int and int->FP moving instructions.
