KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KVERBOSE = 'V=1'
DEBUG ?= 0
ZC ?= 1
PROFILING ?= 1

#EXTRA_CFLAGS +=
ifeq ($(DEBUG),1)
  EXTRA_CFLAGS += -g -DDEBUG
endif
ifeq ($(ZC),1)
EXTRA_CFLAGS += -DZC
endif
ifeq ($(PROFILING),1)
EXTRA_CFLAGS += -DPROFILING
endif

KMAKE_OPTS := -C $(KDIR) M=$(CURDIR)
ifneq ($(ARCH),)
KMAKE_OPTS += ARCH=$(ARCH)
endif
ifneq ($(CROSS_COMPILE),)
KMAKE_OPTS += CROSS_COMPILE=$(CROSS_COMPILE)
endif
ifneq ($(INSTALL_MOD_PATH),)
KMAKE_OPTS += INSTALL_MOD_PATH=$(INSTALL_MOD_PATH)
endif

obj-m := virtio_accel.o
virtio_accel-objs := \
	virtio_accel-core.o \
	virtio_accel-mgr.o \
	virtio_accel-reqs.o \
	virtio_accel-zc.o \
	virtio_accel-sess.o \
	virtio_accel-prof.o \
	accel.o

all: modules

modules:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules

modules_install:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules_install

.PHONY: all clean test_sw test_km

clean:
	$(MAKE) $(KMAKE_OPTS) clean
	rm -f $(USR_TESTS)
