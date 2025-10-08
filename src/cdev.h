// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_CDEV_H
#define _VIRTIO_ACCEL_CDEV_H

#include "core.h"

int virtio_accel_cdev_init(struct virtio_accel *vacl);
void virtio_accel_cdev_cleanup(struct virtio_accel *vacl);

#endif /* _VIRTIO_ACCEL_CDEV_H */
