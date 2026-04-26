obj-m += lha_centos9_resolver.o
obj-m += lha_centos9_injector.o
obj-m += lha_centos9_avc_capture.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
MODULE_BTF ?= auto

KBUILD_ARGS :=

# External module BTF generation in this kernel tree requires $(KDIR)/vmlinux.
# If the headers tree does not provide it, disable the BTF step to avoid the
# noisy "Skipping BTF generation ..." warning during an otherwise successful build.
ifeq ($(MODULE_BTF),0)
KBUILD_ARGS += CONFIG_DEBUG_INFO_BTF_MODULES=
else ifeq ($(MODULE_BTF),auto)
ifeq ($(wildcard $(KDIR)/vmlinux),)
KBUILD_ARGS += CONFIG_DEBUG_INFO_BTF_MODULES=
endif
endif

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KBUILD_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KBUILD_ARGS) clean
