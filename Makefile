CC = gcc
CFLAGS = -Wall -Werror

KVERBOSE = 'V=1'
DEBUG = n

#EXTRA_CFLAGS += -Wno-unused-variable
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -g -DDEBUG=1
else
  EXTRA_CFLAGS += -DDEBUG=0
endif

obj-m := virtio_accel.o
virtio_accel-objs := \
	virtio_accel-core.o \
	virtio_accel-mgr.o \
	virtio_accel-reqs.o
	accel.o \

all: modules

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

modules:
	make -C $(KERNELDIR) $(KVERBOSE) SUBDIRS=$(PWD) modules

test_accel: test_accel.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	make -C $(KERNELDIR) SUBDIRS=$(PWD) clean
	rm -f test_accel
