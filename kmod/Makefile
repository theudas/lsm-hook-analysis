obj-m += lha_centos9_resolver.o
obj-m += lha_centos9_injector.o
obj-m += lha_centos9_avc_capture.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
