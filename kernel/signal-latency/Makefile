all: exception_to_signal_handler hw_to_kernel
PREFIX := riscv64-unknown-linux-gnu-
GCC := $(PREFIX)gcc

exception_to_signal_handler:
	$(GCC) -o exception_to_signal_handler -DUSE_SIGNALS=1 exception_to_signal_handler.c user_fpvm_entry.s -lm
	$(GCC) -o exception_to_kmod_handler exception_to_signal_handler.c user_fpvm_entry.s -lm

hw_to_kernel:
	$(GCC) -o hw_to_kernel  hw_to_kernel.c -lm

clean:
	rm -f hw_to_kernel exception_to_signal_handler


