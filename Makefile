KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR ?= $(CURDIR)/build
KVERBOSE = V=1
DEBUG ?= 0
ZC ?= 1
PROFILING ?= 1

ifeq ($(DEBUG),1)
EXTRA_CFLAGS += -g -DDEBUG
endif
ifeq ($(ZC),1)
EXTRA_CFLAGS += -DZC
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

ccflags-y := -I$(M)
obj-m := virtio_accel.o
virtio_accel-y := \
	virtio_accel-core.o \
	virtio_accel-mgr.o \
	virtio_accel-reqs.o \
	virtio_accel-zc.o \
	virtio_accel-sess.o \
	virtio_accel-prof.o \
	accel.o

.PHONY: all
all: modules

$(BUILD_DIR)/virtio_accel-ver.h: virtio_accel-ver.h.in
	mkdir -p $(BUILD_DIR)
	VERSION=$$(scripts/common/generate-version.sh) ;\
	sed -e "s/@VIRTIO_ACCEL_VERSION@/$${VERSION}/g" < $< > $@

modules: $(BUILD_DIR)/virtio_accel-ver.h
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules

modules_install:
	$(MAKE) $(KMAKE_OPTS) $(KVERBOSE) modules_install

clean:
	$(MAKE) $(KMAKE_OPTS) clean
	rm -f $(BUILD_DIR)/virtio_accel-ver.h
