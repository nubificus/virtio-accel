// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_OP_REQUEST_H
#define _VIRTIO_ACCEL_OP_REQUEST_H

#include <linux/compiler_types.h>

#include "buffer.h"
#include <linux/virtio_accel.h>

struct virtio_accel_op_request {
	struct virtio_accel_op u_op;
	struct virtio_accel_arg *out;
	struct virtio_accel_arg *in;
	struct virtio_accel_buffer *out_bufs;
	struct virtio_accel_buffer *in_bufs;
};

int virtio_accel_op_request_new(struct virtio_accel_op_request **op_req,
				struct virtio_accel_op __user *op);
void virtio_accel_op_request_delete(struct virtio_accel_op_request *op_req);
int virtio_accel_op_request_copy_to_user(struct virtio_accel_op_request *op_req,
					 void __user *op, unsigned int cmd);

#endif /* _VIRTIO_ACCEL_OP_REQUEST_H */
