# GIT_DESC is provided by external include
include version.mk

# To allow sudo make install without mandating root to define PIN_ROOT
ifneq ("$(PIN_ROOT)", "")
    CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
    include $(CONFIG_ROOT)/makefile.config
    include $(TOOLS_ROOT)/Config/makefile.default.rules
endif

TOOL_CXXFLAGS+=-DGIT_DESC=\"$(GIT_DESC)\"

PREFIX=/usr/local

all: intel64


$(OBJDIR)profile.so: $(OBJDIR)profile$(OBJ_SUFFIX)
	$(LINKER) $(TOOL_LDFLAGS) -o $@ $(^:%.h=) $(TOOL_LPATHS) $(TOOL_LIBS)
	ldd $@



intel64:
	echo $(PIN_ROOT)
	mkdir -p obj-intel64
	$(MAKE) TARGET=intel64 obj-intel64/profile.so

clean-all:
	$(MAKE) TARGET=intel64 clean

# install:
# 	cp -a Tracer $(PREFIX)/bin
# 	cp -a obj-* $(PREFIX)/bin
