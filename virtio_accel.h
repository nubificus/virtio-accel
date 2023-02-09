#ifndef _VIRTIO_ACCEL_H
#define _VIRTIO_ACCEL_H

#include <linux/types.h>
#include <linux/virtio_types.h>

#define VIRTIO_ID_ACCEL 21

#define VIRTIO_ACCEL_S_HW_READY  (1 << 0)

/* status */
#define VIRTIO_ACCEL_OK        0
#define VIRTIO_ACCEL_ERR       1
#define VIRTIO_ACCEL_BADMSG    2
#define VIRTIO_ACCEL_NOTSUPP   3
#define VIRTIO_ACCEL_INVSESS   4 /* Invalid session id */

struct virtio_accel_arg {
	__virtio32 len;
	__u8 *buf;
	__u8 __user *usr_buf;
	__u8 *usr_pages;
	__virtio32 usr_npages;
	__u8 padding[5];
};

struct virtio_accel_op {
	__virtio32 in_nr;
	__virtio32 out_nr;
	struct virtio_accel_arg *in;
	struct virtio_accel_arg *out;
};

struct virtio_accel_hdr {
	__virtio32 sess_id;

#define VIRTIO_ACCEL_NO_OP                   0
#define VIRTIO_ACCEL_CREATE_SESSION          1
#define VIRTIO_ACCEL_DESTROY_SESSION         2
#define VIRTIO_ACCEL_DO_OP                   3
#define VIRTIO_ACCEL_GET_TIMERS              4
	__virtio32 op_type;

	/* session create structs */
	struct virtio_accel_op op;
};

struct virtio_accel_conf {
	__u32 status;
	/* Supported service mask */
	__u32 services;
	/* Maximum size of each crypto request's content */
	__u64 max_size;
};

#endif /* _VIRTIO_ACCEL_H */
