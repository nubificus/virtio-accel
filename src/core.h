// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_CORE_H
#define _VIRTIO_ACCEL_CORE_H

#include <linux/miscdevice.h>
#include <linux/types.h>

#include <linux/virtio_accel.h>

struct virtio_accel_virtqueue {
	struct virtqueue *vq;
	spinlock_t lock;

#define VIRTIO_ACCEL_VQ_NAME_LEN 16
	char name[VIRTIO_ACCEL_VQ_NAME_LEN];
};

struct virtio_accel {
	struct virtio_device *vdev;
	struct virtio_accel_virtqueue *vqs;
	struct miscdevice cdev;
	struct module *owner;

	unsigned int num_vqs;
	unsigned int max_req_descriptors;

	struct list_head sessions;
	atomic64_t next_request_id;
};

#endif /* _VIRTIO_ACCEL_CORE_H */
