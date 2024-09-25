# syntax=docker/dockerfile:1.10.0
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04 as linux-builder

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install prerequisites
WORKDIR /
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential gcc g++ ca-certificates wget git bison flex bc \
        libelf-dev libssl-dev cpio pahole kmod && \
    apt-get clean && \
    rm -rf /var/cache/apt /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Get linux source
RUN linux_tag=$(git ls-remote --tags --refs --sort='v:refname' \
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git | \
        grep -E "refs/tags/v6\.1.[0-9]+$" | awk -F/ 'END{print$NF}') && \
    git clone -b "${linux_tag}" --depth 1 \
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

# Create base .config
WORKDIR /linux
ARG DOCKER_DIR=./scripts/docker
COPY "${DOCKER_DIR}"/linux-configs/base.config .
RUN arch=$(echo "${TARGETARCH}" | sed 's/amd64/x86_64/g' | \
        sed 's/arm64/aarch64/g') && \
    wget --progress=bar \
        https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs/microvm-kernel-ci-"${arch}"-6.1.config \
        -O .config && \
    cat base.config >> .config

# Generate Firecracker artifacts
FROM linux-builder as fc-builder

ARG TARGETARCH
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# build linux image
RUN make olddefconfig && \
    ([ "${TARGETARCH}" = "amd64" ] && make -j"$(nproc)" vmlinux || \
        make -j"$(nproc)" Image) && \
    make modules_prepare modules modules_install \
        INSTALL_MOD_PATH=/install/modules

# pack linux image artifacts
WORKDIR /install/linux
ARG PKG_NAME=virtio-accel
ARG PKG_VERSION=0.0.0
RUN version=$(cat /linux/include/config/kernel.release) && \
    cp /linux/.config "linux-${version}-${TARGETARCH}-fc.config" && \
    find /linux \( -name 'vmlinux' -o -name '*Image' \) -exec \
        sh -c 'cp "$1" "$(basename "$1")-$2-$3-fc"' \
            sh {} "${version}" "${TARGETARCH}" \; && \
    tar -pcJf "/install/${PKG_NAME}-${PKG_VERSION}-fc-linux-image.tar.xz" ./*

# build and pack virtio-accel
WORKDIR /virtio-accel
ARG VIRTIO_ACCEL_SRC=.
ARG BUILD_ARGS
RUN --mount=type=bind,rw,target=/virtio-accel,source="${VIRTIO_ACCEL_SRC}" \
    build_dir="$(pwd)/build_$(od -vN 4 -An -tx1 /dev/urandom | tr -d " \n" ; echo)" && \
    eval make modules modules_install \
        KDIR=/linux \
        BUILD_DIR="${build_dir}" \
        INSTALL_MOD_PATH=/install/modules \
        "${BUILD_ARGS}" && \
    tar --acls --xattrs --numeric-owner \
        -JpScf "/install/${PKG_NAME}-${PKG_VERSION}-fc-bin.tar.xz" \
        -C /install/modules .

# Generate generic artifacts
FROM linux-builder as generic-builder

ARG TARGETARCH
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# build linux image
ARG DOCKER_DIR=./scripts/docker
COPY "${DOCKER_DIR}"/linux-configs/generic.config .
RUN cat generic.config >> .config && \
    make olddefconfig && \
    ([ "${TARGETARCH}" = "amd64" ] && make -j"$(nproc)" bzImage || \
        make -j"$(nproc)" Image) && \
    make modules_prepare modules modules_install \
        INSTALL_MOD_PATH=/install/modules

# pack linux image artifacts
WORKDIR /install/linux
ARG PKG_NAME=virtio-accel
ARG PKG_VERSION=0.0.0
RUN version=$(cat /linux/include/config/kernel.release) && \
    cp /linux/.config "linux-${version}-${TARGETARCH}.config" && \
    find /linux -name '*Image' -exec \
        sh -c 'cp "$1" "$(basename "$1")-$2-$3"' \
            sh {} "${version}" "${TARGETARCH}" \; && \
    tar -pcJf "/install/${PKG_NAME}-${PKG_VERSION}-linux-image.tar.xz" ./*

# build and pack virtio-accel
WORKDIR /virtio-accel
ARG VIRTIO_ACCEL_SRC=.
ARG BUILD_ARGS
RUN --mount=type=bind,rw,target=/virtio-accel,source="${VIRTIO_ACCEL_SRC}" \
    build_dir="$(pwd)/build_$(od -vN 4 -An -tx1 /dev/urandom | tr -d " \n" ; echo)" && \
    eval make modules modules_install \
        KDIR=/linux \
        BUILD_DIR="${build_dir}" \
        INSTALL_MOD_PATH=/install/modules \
        "${BUILD_ARGS}" && \
    tar --acls --xattrs --numeric-owner \
        -JpScf "/install/${PKG_NAME}-${PKG_VERSION}-bin.tar.xz" \
        -C /install/modules .

# Copy artifacts to host
FROM scratch as artifacts

COPY --from=fc-builder /install/*.tar.xz /
COPY --from=generic-builder /install/*.tar.xz /
