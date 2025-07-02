#  FPVM - Floating Point Virtual Machine
#
#  Copyright (c) 2021 Peter Dinda - see LICENSE
#

-include config.mk

export FPVM_HOME:=$(shell pwd)
export PATH:=$(FPVM_HOME)/analysis:$(FPVM_HOME)/scripts:$(FPVM_HOME)/analysis/deps/e9patch:$(PATH)

ifeq ($(CONFIG_TOOLCHAIN_PREFIX),"")
  CONFIG_TOOLCHAIN_PREFIX=
endif
PREFIX=$(CONFIG_TOOLCHAIN_PREFIX)

ifeq ($(CONFIG_CAPSTONE_DIR),"")
  CONFIG_CAPSTONE_DIR=
  CAPSTONE_INC=
  CAPSTONE_LINK=-lcapstone
else
  CAPSTONE_INC=-I$(CONFIG_CAPSTONE_DIR)/include
  CAPSTONE_LINK=-L$(CONFIG_CAPSTONE_DIR)/lib -lcapstone
endif

ifeq ($(CONFIG_ARCH_X64),1)
   ARCH=x64
else ifeq ($(CONFIG_ARCH_ARM64),1)
   ARCH=arm64
else ifeq ($(CONFIG_ARCH_RISCV64),1)
   ARCH=riscv64
endif

ARCHSRCDIR = arch/$(ARCH)
ARCHINCDIR = include/arch/$(ARCH)

ARCHSRCS := $(shell find $(ARCHSRCDIR) -name '*.cpp' -or -name '*.c' -or -name '*.s' -or -name "*.S")
GENERICSRCS := $(shell find src -name '*.cpp' -or -name '*.c' -or -name '*.s' -or -name "*.S")
SRCS = $(GENERICSRCS) $(ARCHSRCS)

ARCHINCS := $(shell find $(ARCHINCDIR) -name '*.hpp' -or -name '*.h')
GENERICINCS := $(shell find include -name '*.hpp' -or -name '*.h')
INCS := $(GENERICINCS) $(ARCHINCS)


BUILD?=build
OBJS := $(SRCS:%=$(BUILD)/%.o)
DEPS := $(OBJS:.o=.d)

INC_DIRS := $(ARCHINCDIR)/ include/
INC_FLAGS := $(addprefix -I,$(INC_DIRS)) $(CAPSTONE_INC)

CC = $(PREFIX)gcc
AS = $(PREFIX)gcc
CXX = $(PREFIX)g++
CFLAGS = $(INC_FLAGS) -MMD -MP -O3 -g3 -Wall -Wno-unused-variable -Wno-unused-function -fno-strict-aliasing -Wno-format	-Wno-format-security -D$(ARCH)
CXXFLAGS = -std=c++17 -fno-exceptions -fno-rtti $(CFLAGS)

ifeq ($(CONFIG_HAVE_MAIN),1)
  TARGETS = $(BUILD)/fpvm_main
else
  TARGETS = $(BUILD)/fpvm.so
  TARGETS += $(BUILD)/test_fpvm
endif

ifdef V
  Q ?=
  QPIPE ?=
else
  Q ?= @
  QPIPE ?= >/dev/null 2>&1
endif

ifdef Q
  MAKEFLAGS += -s
  define quiet-cmd =
	@printf "\t%s\t%s\n" "$(1)" "$(2)"
  endef
else
  define quiet-cmd =
  endef
endif


all: $(TARGETS)

.PHONY: what test_lorenz
what:
	@echo "sources:  $(SRCS)"
	@echo "objects:  $(OBJS)"
	@echo "includes: $(INCS)"


# assembly
$(BUILD)/%.s.o: %.s
	@mkdir -p $(dir $@)
	$(call quiet-cmd,AS,$@)
	$(Q)$(AS) -fPIC -shared -c $< -o $@

$(BUILD)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(call quiet-cmd,AS,$@)
	$(Q)$(AS) $(INC_FLAGS) -MMD -MP -fPIC -shared -c $< -o $@

# c source
$(BUILD)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(call quiet-cmd,CC,$@)
	$(Q)$(CC) $(CFLAGS) -std=gnu11 -Wno-discarded-qualifiers -fPIC -shared -c $< -o $@

# c++ source
$(BUILD)/%.cpp.o: %.cpp
	@mkdir -p $(dir $@)
	$(call quiet-cmd,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -fPIC -shared -c $< -o $@

$(TARGET): $(BUILD) $(OBJS)
	$(call quiet-cmd,LD,$@)
	$(Q)cp .config $(BUILD)/.config
	$(Q)cp include/fpvm/config.h $(BUILD)/config.h
	$(Q)$(CC) $(CFLAGS) -fPIC -shared $(OBJS) -o $(TARGET) -Wl,-rpath -Wl,./lib/ -lmpfr -lm -ldl -lstdc++ $(CAPSTONE_LINK)

$(BUILD)/fpvm_main: $(BUILD) $(OBJS)
	$(call quiet-cmd,LD,$@)
	$(Q)$(CC) $(CFLAGS) $(OBJS) -o $(BUILD)/fpvm_main -Wl,-rpath -Wl,./lib/ -lmpfr -lm -ldl -lstdc++ $(CAPSTONE_LINK)

$(BUILD)/test_fpvm: test/test_fpvm.c
	$(CC) $(CFLAGS) -Wno-discarded-qualifiers -O0 -pthread test/test_fpvm.c -lm -o $@

$(BUILD):
	@mkdir -p $(BUILD)

clean:
	@rm -rf $(BUILD)

test: $(TARGET) $(BUILD)/test_fpvm
	@echo ==================================
	LD_PRELOAD=$(TARGET) FPVM_AGGRESSIVE=y $(BUILD)/test_fpvm 2>&1 > test.log



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
