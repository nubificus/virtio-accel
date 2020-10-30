KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KVERBOSE = 'V=1'
DEBUG = 0
ZC = 1

#EXTRA_CFLAGS += -Wno-unused-variable
ifeq ($(DEBUG),1)
  EXTRA_CFLAGS += -g -DDEBUG
endif
ifeq ($(ZC),1)
EXTRA_CFLAGS += -DZC
endif

KMAKE_OPTS := -C $(KDIR) M=$(CURDIR)
ifneq ($(ARCH),)
KMAKE_OPTS += ARCH=$(ARCH)
endif
ifneq ($(CROSS_COMPILE),)
KMAKE_OPTS += CROSS_COMPILE=$(CROSS_COMPILE)
endif

obj-m := virtio_accel.o
virtio_accel-objs := \
	virtio_accel-core.o \
	virtio_accel-mgr.o \
	virtio_accel-reqs.o \
	virtio_accel-zc.o \
	accel.o

all: modules

modules:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules

.PHONY: all clean

clean:
	$(MAKE) $(KMAKE_OPTS) clean
