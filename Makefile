USR_CFLAGS += -Wall
USR_TESTS += test-crypto test-crypto-verify test-dummy_op test-mul_op

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KVERBOSE = 'V=1'
DEBUG = y

#EXTRA_CFLAGS += -Wno-unused-variable
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -g -DDEBUG
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

modules:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules

tests: $(USR_TESTS)

test-%: test-%.c
	$(CC) $(USR_CFLAGS) -o $@ $^

clean:
	$(MAKE) $(KMAKE_OPTS) clean
	rm -f $(USR_TESTS)
