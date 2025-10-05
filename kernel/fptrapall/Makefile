
default:
	@

CURDIR:=$(shell pwd)
KPATH := /lib/modules/$(shell uname -r)/build

obj-m := fptrapall.o

fptrapall-objs += \
	core.o \
	sysfs.o \
	tasks.o \
	dna_patch.o \
	kretprobe_allow_fp.o \
	extra_symbols.o \

all:
	make -C $(KPATH) M=$(CURDIR) modules

clean:
	make -C $(KPATH) M=$(CURDIR) clean

default: all

.PHONY: default all clean

