all: exception_to_signal_handler hw_to_kernel

exception_to_signal_handler:
	gcc -o exception_to_signal_handler  exception_to_signal_handler.c user_fpvm_entry.s -lm

hw_to_kernel:
	gcc -o hw_to_kernel  hw_to_kernel.c -lm

clean:
	rm -f hw_to_kernel exception_to_signal_handler


