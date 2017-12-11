USR_CFLAGS = -Wall -Werror

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
KVERBOSE = 'V=1'
DEBUG = n

#EXTRA_CFLAGS += -Wno-unused-variable
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -g -DDEBUG=1
else
  EXTRA_CFLAGS += -DDEBUG=0
endif

KMAKE_OPTS := -C $(KERNEL_DIR) M=$(CURDIR)
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
	accel.o

all: modules

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

modules:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules

test_accel: test_accel.c
	$(CC) $(USR_CFLAGS) -o $@ $^

clean:
	$(MAKE) $(KMAKE_OPTS) clean
	rm -f test_accel
