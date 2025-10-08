// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_SESSION_H
#define _VIRTIO_ACCEL_SESSION_H

#include <linux/types.h>

#include "request.h"

struct virtio_accel_session {
	u32 id;

#define VIRTIO_ACCEL_TIMERS_BUCKET_CNT (1u << 4) // 16
	struct hlist_head timers[VIRTIO_ACCEL_TIMERS_BUCKET_CNT];

	unsigned int nr_timers;
	struct list_head node;
};

struct virtio_accel_session *
virtio_accel_session_create_and_add(u64 id, struct virtio_accel_request *req);
void virtio_accel_session_delete(u64 id, struct virtio_accel_request *req);
struct virtio_accel_session *
virtio_accel_session_get_by_id(u64 id, struct virtio_accel_request *req);

#endif /* _VIRTIO_ACCEL_SESSION_H */
