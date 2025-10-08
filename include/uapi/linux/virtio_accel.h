// SPDX-License-Identifier: GPL-2.0

#ifndef _LINUX_VIRTIO_ACCEL_H
#define _LINUX_VIRTIO_ACCEL_H

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/virtio_types.h>

/* IOCTLs */
#define VIRTIO_ACCEL_CREATE_SESSION _IOWR('@', 0, struct virtio_accel_op)
#define VIRTIO_ACCEL_DESTROY_SESSION _IOWR('@', 1, __u64)
#define VIRTIO_ACCEL_DO_OP _IOWR('@', 2, struct virtio_accel_op)
#define VIRTIO_ACCEL_GET_TIMERS _IOWR('@', 3, struct virtio_accel_op)

struct virtio_accel_arg {
	__u64 buf;
	__u32 len;
	__u32 type;
	__u32 custom_type_id;
};

struct virtio_accel_op {
	/* Session id */
	__u64 session_id;

	/* User-defined operation code */
	__u32 op_code;

	/* Number of out arguments */
	__u32 nr_out;

	/* Number of in arguments */
	__u32 nr_in;

	/* Pointer to out arguments (struct virtio_accel_arg *) */
	__u64 out;

	/* Pointer to in arguments (struct virtio_accel_arg *) */
	__u64 in;

	/* Operation return value */
	__u32 ret;
};

struct virtio_accel_profiler_sample {
	/* Timestamp (nsec) of entering the region */
	__u64 start;

	/* Time (nsec) elapsed inside the region */
	__u64 time;
};

#define VIRTIO_ACCEL_TIMERS_NAME_MAX 64

struct virtio_accel_profiler_region {
	/* Name of the region */
	char name[VIRTIO_ACCEL_TIMERS_NAME_MAX];

	/* Number of collected samples */
	__u64 nr_entries;

	/* Array of collected samples */
	struct virtio_accel_profiler_sample *samples;

	/* Allocated size for the array */
	__u64 size;
};

/* status */
#define VIRTIO_ACCEL_OK 0
#define VIRTIO_ACCEL_ERR 1
#define VIRTIO_ACCEL_BADMSG 2
#define VIRTIO_ACCEL_NOTSUPP 3
#define VIRTIO_ACCEL_INVSESS 4 /* Invalid session id */

struct virtio_accel_arg_header {
	__virtio32 len;
	__virtio32 type;
	__virtio32 custom_type_id;
};

struct virtio_accel_header {
	__virtio64 request_id;
	__virtio64 session_id;

#define VIRTIO_ACCEL_CMD_CREATE_SESSION 0
#define VIRTIO_ACCEL_CMD_DESTROY_SESSION 1
#define VIRTIO_ACCEL_CMD_DO_OP 2
#define VIRTIO_ACCEL_CMD_GET_TIMERS 3
#define VIRTIO_ACCEL_CMD_MAX 4
	__virtio32 cmd;
	__virtio32 op_code;

	__virtio32 nr_out;
	__virtio32 nr_in;

	__virtio32 total_chunks;
};

struct virtio_accel_config {
	__virtio16 num_queues;
	__virtio16 max_req_descriptors;
};

#endif /* _LINUX_VIRTIO_ACCEL_H */
