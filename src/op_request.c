// SPDX-License-Identifier: GPL-2.0

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "op_request.h"
#include "buffer.h"
#include <linux/virtio_accel.h>

static int get_user_args(struct virtio_accel_arg **args,
			 struct virtio_accel_buffer **arg_bufs, u64 u_addr,
			 unsigned int nr_args, bool write)
{
	int ret;
	int i;

	*args = memdup_user(u64_to_user_ptr(u_addr), nr_args * sizeof(**args));
	if (IS_ERR(*args))
		return PTR_ERR(*args);

	*arg_bufs = kcalloc(nr_args, sizeof(**arg_bufs), GFP_KERNEL);
	if (!*arg_bufs) {
		ret = -ENOMEM;
		goto err_free_args;
	}

	for (i = 0; i < nr_args; i++) {
		struct virtio_accel_arg *arg = &(*args)[i];
		ret = virtio_accel_buffer_init(&(*arg_bufs)[i],
					       u64_to_user_ptr(arg->buf),
					       arg->len, write);
		if (ret)
			goto err_free_bufs;
	}
	return 0;

err_free_bufs:
	while (--i)
		virtio_accel_buffer_release(&(*arg_bufs)[i], write);
	kfree_sensitive(*arg_bufs);
err_free_args:
	kfree_sensitive(*args);
	return ret;
}

static void free_user_args(struct virtio_accel_arg *args,
			   struct virtio_accel_buffer *arg_bufs,
			   unsigned int nr_args, bool write)
{
	if (arg_bufs) {
		for (unsigned int i = 0; i < nr_args; i++)
			virtio_accel_buffer_release(&arg_bufs[i], write);
		kfree_sensitive(arg_bufs);
	}
	kfree_sensitive(args);
}

int virtio_accel_op_request_new(struct virtio_accel_op_request **op_req,
				struct virtio_accel_op __user *op)
{
	struct virtio_accel_op_request *req;
	int ret;

	if (!op_req)
		return -EINVAL;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (!op) {
		*op_req = req;
		return 0;
	}

	if (unlikely(copy_from_user(&req->u_op, op, sizeof(req->u_op))))
		return -EFAULT;

	if (req->u_op.nr_out) {
		ret = get_user_args(&req->out, &req->out_bufs, req->u_op.out,
				    req->u_op.nr_out, false);
		if (ret)
			goto err_free;
	}

	if (req->u_op.nr_in) {
		ret = get_user_args(&req->in, &req->in_bufs, req->u_op.in,
				    req->u_op.nr_in, true);
		if (ret)
			goto err_free_out;
	}

	*op_req = req;
	return 0;

err_free_out:
	free_user_args(req->out, req->out_bufs, req->u_op.nr_out, false);
err_free:
	kfree(req);
	return ret;
}

void virtio_accel_op_request_delete(struct virtio_accel_op_request *op_req)
{
	if (!op_req)
		return;

	free_user_args(op_req->out, op_req->out_bufs, op_req->u_op.nr_out,
		       false);
	free_user_args(op_req->in, op_req->in_bufs, op_req->u_op.nr_in, true);

	kfree(op_req);
}

int virtio_accel_op_request_copy_to_user(struct virtio_accel_op_request *op_req,
					 void __user *op, unsigned int cmd)
{
	struct virtio_accel_op *u_op = &op_req->u_op;
	int ret;

	if (!op_req)
		return -EINVAL;

	if (cmd == VIRTIO_ACCEL_DESTROY_SESSION)
		return 0;

	ret = copy_to_user(op, u_op, sizeof(*u_op));
	if (unlikely(ret))
		return -EINVAL;

	if (!u_op->nr_in || u_op->ret)
		return 0;

	if (unlikely(copy_to_user(u64_to_user_ptr(u_op->in), op_req->in,
				  u_op->nr_in * sizeof(*op_req->in))))
		return -EFAULT;

	for (u32 i = 0; i < u_op->nr_in; i++) {
		ret = virtio_accel_buffer_copy_to_user(&op_req->in_bufs[i]);
		if (ret)
			return ret;
	}

	return 0;
}
