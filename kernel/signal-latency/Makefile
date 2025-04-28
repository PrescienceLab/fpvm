all: exception_to_signal_handler hw_to_kernel
PREFIX := riscv64-unknown-linux-gnu-
GCC := $(PREFIX)gcc
XLEN := 64
CFLAGS := -Wall -Werror

exception_to_signal_handler:
	$(GCC) -static $(CFLAGS) -o exception_to_signal_handler-signal-sigfpe -DUSE_SIGNALS=1 exception_to_signal_handler.c -lm
	$(GCC) -static $(CFLAGS) -o exception_to_signal_handler-pipelined-sigfpe -D__riscv_xlen=$(XLEN) exception_to_signal_handler.c pipelined-xcpt-entry.S -lm

estep:
	$(GCC) -static $(CFLAGS) -o estep-pipelined -D__riscv_xlen=$(XLEN) estep.c pipelined-xcpt-entry.S

hw_to_kernel:
	$(GCC) -o hw_to_kernel  hw_to_kernel.c -lm

clean:
	rm -f hw_to_kernel exception_to_signal_handler
	rm -f exception_to_signal_handler-signal-sigfpe exception_to_signal_handler-pipelined-sigfpe estep-pipelined
