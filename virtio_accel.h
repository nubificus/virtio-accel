// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_H
#define _VIRTIO_ACCEL_H

#include <linux/types.h>
#include <linux/virtio_types.h>

#define VIRTIO_ID_ACCEL 21

#define VIRTIO_ACCEL_S_HW_READY (1 << 0)

/* status */
#define VIRTIO_ACCEL_OK 0
#define VIRTIO_ACCEL_ERR 1
#define VIRTIO_ACCEL_BADMSG 2
#define VIRTIO_ACCEL_NOTSUPP 3
#define VIRTIO_ACCEL_INVSESS 4 /* Invalid session id */

struct virtio_accel_arg_hdr {
	__virtio32 len;
	__virtio32 type;
	__virtio32 custom_type_id;
};

struct virtio_accel_hdr {
	__virtio64 request_id;
	__virtio64 session_id;

#define VIRTIO_ACCEL_CMD_CREATE_SESSION 0
#define VIRTIO_ACCEL_CMD_DESTROY_SESSION 1
#define VIRTIO_ACCEL_CMD_DO_OP 2
#define VIRTIO_ACCEL_CMD_GET_TIMERS 3
#define VIRTIO_ACCEL_CMD_MAX 4
	__virtio32 cmd;
	__virtio32 op_code;

	__virtio32 out_nr;
	__virtio32 in_nr;

	__virtio32 total_chunks;
};

struct virtio_accel_conf {
	__u32 status;
	/* Supported service mask */
	__u32 services;
	/* Maximum size of each crypto request's content */
	__u64 max_size;
};

#endif /* _VIRTIO_ACCEL_H */
