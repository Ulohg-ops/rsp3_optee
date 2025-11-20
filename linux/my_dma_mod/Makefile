obj-m := my_kmod.o

CROSS_COMPILE := /home/ulohg/rpi3_optee/toolchains/aarch64/bin/aarch64-linux-gnu-
ARCH := arm64

KDIR := /home/ulohg/rpi3_optee/linux
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
