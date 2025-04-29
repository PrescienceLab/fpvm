#  FPVM - Floatng Point Virtual Machine
#
#  Copyright (c) 2021 Peter Dinda - see LICENSE
#

export FPVM_HOME:=$(shell pwd)
export PATH:=$(FPVM_HOME)/analysis:$(FPVM_HOME)/scripts:$(FPVM_HOME)/analysis/deps/e9patch:$(PATH)

# this should come from from config... 
ARCH=x64
#ARCH=riscv64

# hard coded assuming we are doing cross-compilation
ifeq ($(ARCH),riscv64)
  PREFIX=riscv64-unknown-linux-gnu-
else
  PREFIX=
endif


ARCHSRCDIR = arch/$(ARCH)
ARCHINCDIR = $(ARCHSRCDIR)

ARCHSRCS := $(shell find $(ARCHSRCDIR) -name '*.cpp' -or -name '*.c' -or -name '*.s' -or -name "*.S")
GENERICSRCS := $(shell find src -name '*.cpp' -or -name '*.c' -or -name '*.s' -or -name "*.S")
SRCS = $(GENERICSRCS) $(ARCHSRCS)

ARCHINCS := $(shell find $(ARCHINCDIR) -name '*.hpp' -or -name '*.h')
GENERICINCS := $(shell find include -name '*.hpp' -or -name '*.h')
INCS := $(GENERICINCS) $(ARCHINCS)


BUILD?=build
OBJS := $(SRCS:%=$(BUILD)/%.o)
DEPS := $(OBJS:.o=.d)

INC_DIRS := include/ $(ARCHINCDIR)/
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CC = $(PREFIX)gcc
AS = $(PREFIX)gcc
CXX = $(PREFIX)g++
CFLAGS = $(INC_FLAGS) -MMD -MP -O3 -g3 -Wall -Wno-unused-variable -Wno-unused-function -fno-strict-aliasing -Wno-format	-Wno-format-security
CXXFLAGS = -std=c++17 -fno-exceptions -fno-rtti $(CFLAGS)

TARGET=$(BUILD)/fpvm.so

all: $(TARGET) # $(BUILD)/test_fpvm

.PHONY: foo test_lorenz
foo:
	@echo "sources:  $(SRCS)"
	@echo "objects:  $(OBJS)"
	@echo "includes: $(INCS)"

# assembly
$(BUILD)/%.s.o: %.s
	@@mkdir -p $(dir $@)
	@echo " AS   $<"
	@$(AS) -fPIC -shared -c $< -o $@

$(BUILD)/%.S.o: %.S
	@mkdir -p $(dir $@)
	@echo " AS   $<"
	@$(AS) $(INC_FLAGS) -MMD -MP -fPIC -shared -c $< -o $@

# c source
$(BUILD)/%.c.o: %.c
	@mkdir -p $(dir $@)
	@echo " CC   $<"
	@$(CC) $(CFLAGS) -Wno-discarded-qualifiers -fPIC -shared -c $< -o $@

# c++ source
$(BUILD)/%.cpp.o: %.cpp
	@mkdir -p $(dir $@)
	@echo " CXX  $<"
	@$(CXX) $(CXXFLAGS) -fPIC -shared -c $< -o $@

$(TARGET): $(BUILD) $(OBJS) 
	@echo " LD   $(TARGET)"
	@cp .config $(BUILD)/.config
	@cp include/fpvm/config.h $(BUILD)/config.h
	@$(CC) $(CFLAGS) -fPIC -shared $(OBJS) -o $(TARGET) -Wl,-rpath -Wl,./lib/ -lmpfr -lm -ldl -lstdc++ -lcapstone

$(BUILD)/fpvm_main: $(BUILD) $(OBJS) 
	@echo " LD   $(BUILD)/fpvm_main"
	@$(CC) $(CFLAGS) $(OBJS) -o $(BUILD)/fpvm_main -Wl,-rpath -Wl,./lib/ -lmpfr -lm -ldl -lstdc++ -lcapstone



$(BUILD)/vmtest: $(BUILD) $(OBJS) bin/vmtest.c
	@$(CC) $(CFLAGS) bin/vmtest.c src/vm.c -o $(BUILD)/vmtest -Wl,-rpath -Wl,./lib/-lm -ldl


$(BUILD)/test_fpvm: test_fpvm.c
	$(CC) $(CFLAGS) -Wno-discarded-qualifiers -O0 -pthread test_fpvm.c -lm -o $@

$(BUILD):
	@mkdir -p $(BUILD)

clean:
	@rm -rf $(BUILD)

test: $(TARGET) $(BUILD)/test_fpvm
	@echo ==================================
	LD_PRELOAD=$(TARGET) FPVM_AGGRESSIVE=y $(BUILD)/test_fpvm 2>&1 > test.log



test_miniaero: $(TARGET) $(BUILD)/test_fpvm
	@echo ==================================
	LD_PRELOAD=$(TARGET) FPVM_AGGRESSIVE=y test/miniaero_patched



test/lorenz_attractor: test/lorenz_attractor.cpp
	@[ -d "test/boost" ] || ( \
	wget -O test/boost.tar.gz https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.gz && \
	tar -C test/ -xvf test/boost.tar.gz && mv test/boost_1_78_0 test/boost \
	)
	g++ -std=c++11 -fno-PIC -no-pie -pthread -lm -I ./test/boost/ -O3 test/lorenz_attractor.cpp -o test/lorenz_attractor

test/lorenz_attractor.patched: test/lorenz_attractor
	./patch.sh test/lorenz_attractor


test_lorenz: $(TARGET) test/lorenz_attractor.patched
	@echo ==================================
	LD_PRELOAD=$(TARGET) FPVM_AGGRESSIVE=y test/lorenz_attractor.patched


test/double_pendulum: test/double_pendulum.cpp
	g++ -std=c++11 -fno-PIC -no-pie -lm -O3 test/double_pendulum.cpp -o test/double_pendulum
test/double_pendulum.patched: test/double_pendulum
	./patch.sh test/double_pendulum


lorenz: test/lorenz_attractor


test_enzo: $(TARGET) $(BUILD)/test_fpvm
	@echo ==================================
	@echo source env.sh first !
	@echo ==================================
	LD_PRELOAD=$(TARGET) FPVM_AGGRESSIVE=y test/enzo/enzo_patched -d test/enzo/input

test_fbench: $(TARGET) $(BUILD)/test_fpvm
	@echo ==================================
	LD_PRELOAD=$(TARGET) FPVM_AGGRESSIVE=y DISABLE_PTHREADS=y test/fbench_patched

menuconfig:
	@scripts/menuconfig.py

defconfig:
	@rm -f .config
	@echo "Using default configuration"
	@echo "q" | env TERM=xterm-256color python3 scripts/menuconfig.py >/dev/null

cfg:
	@scripts/menuconfig.py

# run `make reconfig` if `.config` has changed.
reconfig:
	@touch .config
	@echo -e "q" | env TERM=xterm-256color python3 scripts/menuconfig.py >/dev/null


-include $(DEPS)
