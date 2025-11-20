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
#include "core.h"
#include "profiler.h"
#include "session.h"
#include <linux/virtio_accel.h>

static int get_user_args(struct virtio_accel_arg **args,
			 struct virtio_accel_buffer **arg_bufs, u64 u_addr,
			 unsigned int nr_args, bool write)
{
	int ret;
	unsigned int i;

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

static int get_user_regions(struct virtio_accel_profiler_region **regions,
			    struct virtio_accel_buffer **samples_bufs,
			    u64 u_addr, unsigned int nr_regions)
{
	int ret;
	unsigned int i;

	*regions = memdup_user(u64_to_user_ptr(u_addr),
			       nr_regions * sizeof(**regions));
	if (IS_ERR(*regions))
		return PTR_ERR(*regions);

	*samples_bufs = kcalloc(nr_regions, sizeof(**samples_bufs), GFP_KERNEL);
	if (!*samples_bufs) {
		ret = -ENOMEM;
		goto err_free_regions;
	}

	for (i = 0; i < nr_regions; i++) {
		struct virtio_accel_profiler_region *region = &(*regions)[i];
		size_t samples_size =
			region->max_samples *
			sizeof(struct virtio_accel_profiler_sample);
		ret = virtio_accel_buffer_init(&(*samples_bufs)[i],
					       u64_to_user_ptr(region->samples),
					       samples_size, true);
		if (ret)
			goto err_free_bufs;

		struct virtio_accel_profiler_sample *samples =
			(struct virtio_accel_profiler_sample *)
				virtio_accel_buffer_map(&(*samples_bufs)[i]);
		if (!samples) {
			ret = -ENOMEM;
			goto err_free_bufs;
		}
	}

	return 0;

err_free_bufs:
	while (--i)
		virtio_accel_buffer_release(&(*samples_bufs)[i], true);
	kfree(*samples_bufs);
err_free_regions:
	kfree(*regions);
	return ret;
}

static void free_user_regions(struct virtio_accel_profiler_region *regions,
			      struct virtio_accel_buffer *samples_bufs,
			      unsigned int nr_regions)
{
	if (samples_bufs) {
		for (unsigned int i = 0; i < nr_regions; i++)
			virtio_accel_buffer_release(&samples_bufs[i], true);
		kfree(samples_bufs);
	}
	kfree(regions);
}

static int init_request_from_session(struct virtio_accel_op_request *req,
				     const u64 __user *sess_id)
{
	if (unlikely(!req || !sess_id))
		return -EINVAL;

	if (unlikely(get_user(req->op.u_op.session_id, sess_id)))
		return -EFAULT;

	return 0;
}

static int
init_request_from_profiler_op(struct virtio_accel_op_request *req,
			      struct virtio_accel_profiler_op __user *op)
{
	struct virtio_accel_profiler_op *u_op;
	int ret;

	if (unlikely(!req || !op))
		return -EINVAL;

	u_op = &req->profiler_op.u_op;
	if (unlikely(copy_from_user(u_op, op, sizeof(*u_op))))
		return -EFAULT;

	if (u_op->max_regions) {
		ret = get_user_regions(&req->profiler_op.regions,
				       &req->profiler_op.samples_bufs,
				       u_op->regions, u_op->max_regions);
		if (ret)
			return ret;
	}

	return 0;
}

static int init_request_from_op(struct virtio_accel_op_request *req,
				struct virtio_accel_op __user *op,
				struct virtio_accel *vacl)
{
	struct virtio_accel_op *u_op;
	struct virtio_accel_session *sess = NULL;
	int ret;

	if (unlikely(!req || !op))
		return -EINVAL;

	u_op = &req->op.u_op;
	if (unlikely(copy_from_user(u_op, op, sizeof(*u_op))))
		return -EFAULT;

	if (req->cmd == VIRTIO_ACCEL_DO_OP) {
		sess = virtio_accel_session_get_by_id(vacl, u_op->session_id);
		virtio_accel_profiler_timer_start(sess, "get user args");
	}

	if (u_op->nr_out) {
		ret = get_user_args(&req->op.out, &req->op.out_bufs, u_op->out,
				    u_op->nr_out, false);
		if (ret)
			return ret;
	}

	if (u_op->nr_in) {
		ret = get_user_args(&req->op.in, &req->op.in_bufs, u_op->in,
				    u_op->nr_in, true);
		if (ret) {
			free_user_args(req->op.out, req->op.out_bufs,
				       u_op->nr_out, false);
			return ret;
		}
	}

	virtio_accel_profiler_timer_stop(sess, "get user args");
	return 0;
}

int virtio_accel_op_request_new(struct virtio_accel_op_request **op_req,
				unsigned int cmd, void __user *arg,
				struct virtio_accel *vacl)
{
	struct virtio_accel_op_request *req;
	int ret;

	if (!op_req || !arg)
		return -EINVAL;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->cmd = cmd;

	if (cmd == VIRTIO_ACCEL_DESTROY_SESSION) {
		ret = init_request_from_session(req, (u64 *)arg);
		if (ret)
			goto err_free;
	} else if (cmd == VIRTIO_ACCEL_GET_TIMERS) {
		ret = init_request_from_profiler_op(
			req, (struct virtio_accel_profiler_op *)arg);
		if (ret)
			goto err_free;
	} else {
		ret = init_request_from_op(req, (struct virtio_accel_op *)arg,
					   vacl);
		if (ret)
			goto err_free;
	}

	*op_req = req;
	return 0;

err_free:
	kfree(req);
	return ret;
}

void virtio_accel_op_request_delete(struct virtio_accel_op_request *op_req)
{
	if (!op_req)
		return;

	if (op_req->cmd == VIRTIO_ACCEL_GET_TIMERS) {
		free_user_regions(op_req->profiler_op.regions,
				  op_req->profiler_op.samples_bufs,
				  op_req->profiler_op.u_op.nr_regions);
	} else {
		free_user_args(op_req->op.out, op_req->op.out_bufs,
			       op_req->op.u_op.nr_out, false);
		free_user_args(op_req->op.in, op_req->op.in_bufs,
			       op_req->op.u_op.nr_in, true);
	}

	kfree(op_req);
}

static int copy_profiler_op_to_user(struct virtio_accel_op_request *op_req,
				    void __user *op)
{
	struct virtio_accel_profiler_op *u_op;
	int ret;

	if (!op_req || !op)
		return -EINVAL;

	u_op = &op_req->profiler_op.u_op;
	if (unlikely(copy_to_user(op, u_op, sizeof(*u_op))))
		return -EINVAL;

	if (!u_op->max_regions || u_op->ret)
		return 0;

	if (unlikely(copy_to_user(
		    u64_to_user_ptr(u_op->regions), op_req->profiler_op.regions,
		    u_op->nr_regions * sizeof(*op_req->profiler_op.regions))))
		return -EFAULT;

	for (unsigned int i = 0; i < u_op->nr_regions; i++) {
		ret = virtio_accel_buffer_copy_to_user(
			&op_req->profiler_op.samples_bufs[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int copy_op_to_user(struct virtio_accel_op_request *op_req,
			   void __user *op)
{
	struct virtio_accel_op *u_op;
	int ret;

	if (!op_req || !op)
		return -EINVAL;

	u_op = &op_req->op.u_op;
	if (unlikely(copy_to_user(op, u_op, sizeof(*u_op))))
		return -EINVAL;

	if (!u_op->nr_in || u_op->ret)
		return 0;

	if (unlikely(copy_to_user(u64_to_user_ptr(u_op->in), op_req->op.in,
				  u_op->nr_in * sizeof(*op_req->op.in))))
		return -EFAULT;

	for (unsigned int i = 0; i < u_op->nr_in; i++) {
		ret = virtio_accel_buffer_copy_to_user(&op_req->op.in_bufs[i]);
		if (ret)
			return ret;
	}

	return 0;
}

int virtio_accel_op_request_copy_to_user(struct virtio_accel_op_request *op_req,
					 void __user *arg)
{
	if (!op_req || !arg)
		return -EINVAL;

	if (op_req->cmd == VIRTIO_ACCEL_DESTROY_SESSION)
		return 0;

	if (op_req->cmd == VIRTIO_ACCEL_GET_TIMERS)
		return copy_profiler_op_to_user(op_req, arg);

	return copy_op_to_user(op_req, arg);
}
