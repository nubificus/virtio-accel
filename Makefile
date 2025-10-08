KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR ?= $(CURDIR)/build
KVERBOSE = V=1
DEBUG ?= 0
PROFILING ?= 1

ifeq ($(DEBUG),1)
EXTRA_CFLAGS += -g -DDEBUG
endif
ifeq ($(PROFILING),1)
EXTRA_CFLAGS += -DPROFILING
endif

KMAKE_OPTS := -C $(KDIR) src=$(CURDIR) M=$(BUILD_DIR)
ifneq ($(ARCH),)
KMAKE_OPTS += ARCH=$(ARCH)
endif
ifneq ($(CROSS_COMPILE),)
KMAKE_OPTS += CROSS_COMPILE=$(CROSS_COMPILE)
endif
ifneq ($(INSTALL_MOD_PATH),)
KMAKE_OPTS += INSTALL_MOD_PATH=$(INSTALL_MOD_PATH)
endif

ifneq ($(KERNELRELEASE),)
KVERSION = $(KERNELRELEASE)
else
KVERSION := $(shell $(MAKE) -s -C $(KDIR) kernelversion)
endif

KVERSION_OK := $(shell \
	MAJOR=$$(echo $(KVERSION) | cut -d. -f1); \
	MINOR=$$(echo $(KVERSION) | cut -d. -f1); \
	if [ $${MAJOR} -lt 5 ] || ([ $${MAJOR} -eq 5 ] && [ $${MINOR} -lt 10 ]); \
	then \
		echo 0; \
	else \
		echo 1; \
	fi)

ifneq ($(KVERSION_OK),1)
$(error Kernel $(KVERSION) < 5.10.0 is not supported)
endif

ccflags-y := -I$(M)/src
ccflags-y += -I$(src)/include
ccflags-y += -I$(src)/include/uapi
obj-m := virtio_accel.o
virtio_accel-y := \
	src/buffer.o \
	src/cdev.o \
	src/core.o \
	src/op_request.o \
	src/profiler.o \
	src/request.o \
	src/session.o

.PHONY: all clean
all: modules

$(BUILD_DIR)/src/version.h: src/version.h.in
	mkdir -p $(BUILD_DIR)/src
	VERSION=$$(scripts/common/generate-version.sh) ;\
	sed -e "s/@VIRTIO_ACCEL_VERSION@/$${VERSION}/g" < $< > $@

modules: $(BUILD_DIR)/src/version.h
	$(MAKE) CC=$(CC) $(KMAKE_OPTS) $(KVERBOSE) $@

compile_commands.json: modules
	$(MAKE) CC=$(CC) $(KMAKE_OPTS) $(KVERBOSE) $@

modules_install:
	$(MAKE) CC=$(CC) $(KMAKE_OPTS) $(KVERBOSE) $@

clean:
	$(MAKE) CC=$(CC) $(KMAKE_OPTS) $@
	rm -f $(BUILD_DIR)/src/version.h
