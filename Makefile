USR_CPPFLAGS := $(USR_CPPFLAGS) -Wall
USR_TESTS := test-crypto test-crypto-verify test-dummy_op test-mul_op \
			 test-mul_op-verify test-crypto_op test-crypto_op-verify \
			 test-class_op test-det_op test-seg_op

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KVERBOSE = 'V=1'
DEBUG = n

#EXTRA_CFLAGS += -Wno-unused-variable
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -g -DDEBUG
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
	accel.o

all: modules

modules:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules

modules_install:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules_install

tests: $(USR_TESTS) test_sw test_km

test-%: test-%.c
	$(CC) $(USR_CFLAGS) -o $@ $^

clean: test_sw
test_sw: CPPFLAGS := $(CPPFLAGS) -I. -W -Wall -Wno-unknown-pragmas \
					-fno-common -O2 -g -fopenmp $(USR_CPPFLAGS)
export CPPFLAGS
test_sw: CFLAGS := $(CPPFLAGS)
export CFLAGS
test_sw: CXXFLAGS := $(CXXFLAGS) $(CPPFLAGS) -fpermissive
export CXXFLAGS
test_sw: LDFLAGS := $(LDFLAGS) -L. -fopenmp
export LDFLAGS
test_sw:
	$(MAKE) -C smithwaterman $(MAKECMDGOALS)

clean: test_km
test_km: CPPFLAGS := $(CPPFLAGS) -I. -W -Wall -Wno-unknown-pragmas \
					-fno-common -O2 -g $(USR_CPPFLAGS)
export CPPFLAGS
test_km: CFLAGS := $(CPPFLAGS)
export CFLAGS
test_km: CXXFLAGS := $(CXXFLAGS) $(CPPFLAGS) -fpermissive
export CXXFLAGS
test_km: LDFLAGS := $(LDFLAGS) -L.
export LDFLAGS
test_km:
	$(MAKE) -C kmeans $(MAKECMDGOALS)

.PHONY: all clean test_sw test_km

clean:
	$(MAKE) $(KMAKE_OPTS) clean
	rm -f $(USR_TESTS)
