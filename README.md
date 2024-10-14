# virtio-accel Linux kernel module

The virtio-accel Linux kernel module implements VirtIO-based transport
for acceleration operations. It is meant as a lightweight alternative
to vSock for [vAccel](https://github.com/nubificus/vaccel) VM execution.

Following the split-driver VirtIO model, the transport functionality is
implemented in two parts: a) this kernel module, and b) a
[QEMU](https://github.com/cloudkernels/qemu-vaccel) driver
<!-- TODO: Add firecracker info -->

## Prebuilt artifacts

You can get the latest VM artifacts, including virtio-accel and a Linux
kernel image, using:
```bash
wget https://s3.nbfc.io/nbfc-assets/github/vaccel/virtio-accel/rev/main/${ARCH}/release/virtio-accel-latest-bin.tar.xz
wget https://s3.nbfc.io/nbfc-assets/github/vaccel/virtio-accel/rev/main/${ARCH}/release/virtio-accel-latest-linux-image.tar.xz
```
by setting `ARCH=x86_64` or `ARCH=aarch64` depending on your architecture.

There is also a Docker image with QEMU pre-installed:
```bash
docker pull harbor.nbfc.io/nubificus/qemu-vaccel:${ARCH}
```

## Build virtio-accel

To build the virtio-accel module you will need the Linux kernel
headers for your VM's kernel. To install the headers on a VM with a
Debian-based distro you can use:
```bash
sudo apt install linux-headers-$(uname -r)
```

Get the plugin:
```bash
git clone https://github.com/nubificus/virtio-accel
cd virtio-accel
```

To then build virtio-accel with meson:
```bash
meson setup build
meson compile -C build
```

You can also configure a custom kernel source directory using the `kdir`
option, ie:
```bash
meson setup --reconfigure -Dkdir=/path/to/kernel/source build
```

A plain make implementation is also available:
```bash
make modules
```
or
```bash
make modules KDIR=/path/to/kernel/source

```

Alternatively, artifacts to use for a VM can be built with:
```bash
ninja gen-vm-artifacts -C build
```
using an already configured meson `build` directory. This target
requires a working [Docker](https://www.docker.com/) installation.

## Build QEMU

To use the virtio-accel module you will also need a compatible QEMU
build.

To fetch and build QEMU:
```bash
git clone https://github.com/cloudkernels/qemu-vaccel
mkdir qemu-vaccel/build
cd qemu-vaccel/build
../configure --target-list=${ARCH}-softmmu --enable-virtfs && \
make -j$(nproc)
```
