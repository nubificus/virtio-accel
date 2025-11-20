// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "request.h"
#include "buffer.h"
#include "common.h"
#include "core.h"
#include "op_request.h"
#include "profiler.h"
#include "session.h"
#include <linux/virtio_accel.h>

struct virtio_accel_request *
virtio_accel_request_new(struct virtio_accel *vacl, u32 cmd,
			 struct virtio_accel_op_request *op_req)
{
	struct virtio_accel_request *req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->vacl = vacl;
	req->cmd = cmd;
	atomic_set(&req->chunk_count, 0);
	req->op_req = op_req;

	init_completion(&req->completion);
	return req;
}

struct virtio_accel_request *
virtio_accel_request_new_with_parent(struct virtio_accel_request *parent)
{
	struct virtio_accel_request *req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->vacl = parent->vacl;
	req->cmd = parent->cmd;
	req->parent = parent;
	atomic_set(&req->chunk_count, 0);
	req->op_req = parent->op_req;

	init_completion(&req->completion);
	return req;
}

void virtio_accel_request_delete(struct virtio_accel_request *req)
{
	if (!req)
		return;

	if (req->parent)
		atomic_dec(&req->parent->chunk_count);
	else if (!completion_done(&req->completion))
		return;

	if (req->cmd == VIRTIO_ACCEL_CMD_GET_TIMERS) {
		kfree(req->timer_hdrs.regions);
		kfree(req->timer_hdrs.samples);
	} else {
		kfree_sensitive(req->arg_hdrs.out);
		kfree_sensitive(req->arg_hdrs.in);
	}

	for (unsigned int i = 0; i < req->sg_allocs.count; i++)
		kfree(req->sg_allocs.allocs[i]);

	kfree(req->sg_allocs.allocs);
	kfree(req->sgs);
	kfree(req);
}

static int prepare_arg_headers(struct virtio_accel_arg_header **arg_hdrs,
			       struct virtio_accel_arg *args, u32 nr_args,
			       bool write, struct virtio_device *vdev)
{
	struct virtio_accel_arg_header *hdrs;
	unsigned int i;

	if (!arg_hdrs || (nr_args && !args) || !vdev)
		return -EINVAL;

	if (!nr_args) {
		*arg_hdrs = NULL;
		return 0;
	}

	hdrs = kzalloc_node(nr_args * sizeof(*hdrs), GFP_KERNEL,
			    dev_to_node(&vdev->dev));
	if (!hdrs)
		return -ENOMEM;

	for (i = 0; i < nr_args; i++) {
		hdrs[i].len = cpu_to_virtio32(vdev, args[i].len);
		hdrs[i].type = cpu_to_virtio32(vdev, args[i].type);
		hdrs[i].custom_type_id =
			cpu_to_virtio32(vdev, args[i].custom_type_id);
	}

	*arg_hdrs = hdrs;
	return (int)nr_args;
}

static int prepare_request_with_args(struct virtio_accel_request *req,
				     struct virtio_accel_op_request *op_req,
				     struct virtio_device *vdev)
{
	struct virtio_accel_header *h;
	struct virtio_accel_op *u_op;
	int ret;
	int total_sgs = 0;

	if (!req || !op_req)
		return -EINVAL;

	h = &req->hdr;
	u_op = &op_req->op.u_op;

	vacl_debug(
		"Request session_id=%llu, cmd=%u, op_code=%u, nr_out=%u, nr_in=%u\n",
		u_op->session_id, req->cmd, u_op->op_code, u_op->nr_out,
		u_op->nr_in);

	h->session_id = cpu_to_virtio32(vdev, u_op->session_id);
	h->cmd = cpu_to_virtio32(vdev, req->cmd);
	h->op.op_code = cpu_to_virtio32(vdev, u_op->op_code);

	ret = prepare_arg_headers(&req->arg_hdrs.out, op_req->op.out,
				  u_op->nr_out, 0, vdev);
	if (ret < 0)
		return ret;

	total_sgs += ret + 1;
	h->op.nr_out = cpu_to_virtio32(vdev, u_op->nr_out);

	ret = prepare_arg_headers(&req->arg_hdrs.in, op_req->op.in, u_op->nr_in,
				  1, vdev);
	if (ret < 0)
		goto free_out;

	total_sgs += ret + 1;
	h->op.nr_in = cpu_to_virtio32(vdev, u_op->nr_in);

	if ((op_req->op.out_bufs && !op_req->op.out_bufs[0].pinned) ||
	    (op_req->op.in_bufs && !op_req->op.in_bufs[0].pinned)) {
		size_t nr_sg_allocs = 2;
		req->sg_allocs.allocs = kcalloc(nr_sg_allocs,
						sizeof(*req->sg_allocs.allocs),
						GFP_KERNEL);
		if (!req->sg_allocs.allocs)
			return -ENOMEM;

		req->sg_allocs.capacity = nr_sg_allocs;
	}

	return total_sgs;

free_out:
	kfree_sensitive(req->arg_hdrs.out);
	h->op.nr_out = 0;
	return ret;
}

static int prepare_request_with_timers(struct virtio_accel_request *req,
				       struct virtio_accel_op_request *op_req,
				       struct virtio_device *vdev,
				       unsigned int *region_hdrs_size,
				       unsigned int *sample_hdrs_size)
{
	struct virtio_accel_header *h;
	struct virtio_accel_profiler_op *u_op;
	struct virtio_accel_profiler_region_hdr *region_hdrs;
	struct virtio_accel_profiler_sample_hdr *sample_hdrs;
	struct virtio_accel_session *sess;
	unsigned int nr_v_regions;
	unsigned int total_max_samples = 0;
	unsigned int i;
	int total_sgs = 2; // regions + samples

	if (!req || !op_req ||
	    (op_req->profiler_op.u_op.max_regions &&
	     !op_req->profiler_op.regions) ||
	    !vdev)
		return -EINVAL;

	h = &req->hdr;
	u_op = &op_req->profiler_op.u_op;

	vacl_debug("Request session_id=%llu, cmd=%u, max_regions=%u\n",
		   u_op->session_id, req->cmd, u_op->max_regions);

	h->session_id = cpu_to_virtio32(vdev, u_op->session_id);
	h->cmd = cpu_to_virtio32(vdev, req->cmd);

	if (!u_op->max_regions) {
		req->timer_hdrs.regions = NULL;
		req->timer_hdrs.samples = NULL;
		return 0;
	}

	sess = virtio_accel_session_get_by_id(req->vacl, u_op->session_id);
	if (!sess)
		return -EINVAL;

	/* Only populate profiler headers for VMM regions */
	if (u_op->max_regions <= sess->nr_timers)
		return 0;

	nr_v_regions = u_op->max_regions - sess->nr_timers;
	region_hdrs = kcalloc_node(nr_v_regions, sizeof(*region_hdrs),
				   GFP_KERNEL, dev_to_node(&vdev->dev));
	if (!region_hdrs)
		return -ENOMEM;

	for (i = 0; i < nr_v_regions; i++) {
		unsigned int v_pos = sess->nr_timers + i;
		region_hdrs[i].max_samples = cpu_to_virtio32(
			vdev, op_req->profiler_op.regions[v_pos].max_samples);
		total_max_samples +=
			op_req->profiler_op.regions[v_pos].max_samples;
	}

	sample_hdrs = kcalloc_node(total_max_samples, sizeof(*sample_hdrs),
				   GFP_KERNEL, dev_to_node(&vdev->dev));
	if (!sample_hdrs) {
		kfree(region_hdrs);
		return -ENOMEM;
	}

	h->profiler_op.max_regions = nr_v_regions;
	req->timer_hdrs.regions = region_hdrs;
	req->timer_hdrs.samples = sample_hdrs;

	if (region_hdrs_size)
		*region_hdrs_size = nr_v_regions * sizeof(*region_hdrs);
	if (sample_hdrs_size)
		*sample_hdrs_size = total_max_samples * sizeof(*sample_hdrs);

	return total_sgs;
}

static int sg_add_buf(struct scatterlist **sgs, struct scatterlist *sg,
		      void *buf, unsigned int size)
{
	if (!sgs || !buf || !size)
		return -EINVAL;

	sg_init_one(sg, buf, size);
	*sgs = sg;

	return 1;
}

static int sg_add_arg_buf(struct scatterlist **sgs, struct scatterlist *sg,
			  struct virtio_accel_buffer *arg_buf)
{
	if (!sgs || !arg_buf || (!arg_buf->pinned && !sg))
		return -EINVAL;

	if (arg_buf->pinned)
		*sgs = arg_buf->sgt->sgl;
	else
		sg_add_buf(sgs, sg, arg_buf->buf, arg_buf->len);

	return 1;
}

static int sg_add_args(struct scatterlist **sgs, struct scatterlist *hdr_sg,
		       struct virtio_accel_sg_allocs *sg_allocs,
		       struct virtio_accel_arg_header *arg_hdrs,
		       struct virtio_accel_buffer *arg_bufs, u32 nr_args,
		       struct virtio_device *vdev)
{
	struct scatterlist *arg_sgs = NULL;
	int i;
	int ret;

	if (!sgs || !hdr_sg || (nr_args && (!arg_hdrs || !arg_bufs)) || !vdev)
		return -EINVAL;

	if (!nr_args)
		return 0;

	if (!arg_bufs[0].pinned) {
		arg_sgs = kmalloc_array_node(nr_args, sizeof(*arg_sgs),
					     GFP_KERNEL,
					     dev_to_node(&vdev->dev));
		if (!arg_sgs)
			return -ENOMEM;

		if (sg_allocs) {
			if (sg_allocs->count == sg_allocs->capacity) {
				vacl_err("Failed to store SG allocations\n");
				return -EINVAL;
			}

			sg_allocs->allocs[sg_allocs->count++] = arg_sgs;
		}
	}

	ret = sg_add_buf(&sgs[0], hdr_sg, arg_hdrs,
			 nr_args * sizeof(*arg_hdrs));
	if (ret < 0) {
		vacl_err("Failed to add argument headers\n");
		return ret;
	}

	for (i = 0; i < nr_args; i++) {
		struct scatterlist *sg = arg_sgs ? &arg_sgs[i] : NULL;

		ret = sg_add_arg_buf(&sgs[i + 1], sg, &arg_bufs[i]);
		if (ret < 0) {
			vacl_err(
				"Failed to add argument %d buffer (size: %u)\n",
				i, arg_bufs[i].len);
			kfree(arg_sgs);
			return ret;
		}
	}

	return i + 1;
}

static int submit_req_with_args(struct virtio_accel_request *req)
{
	struct virtio_accel *vacl = req->vacl;
	struct virtio_device *vdev = vacl->vdev;
	struct virtio_accel_header *h = &req->hdr;
	struct virtio_accel_op_request *op_req = req->op_req;
	struct virtio_accel_op *u_op = &op_req->op.u_op;
	bool has_sess_id = (req->cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION);
	bool has_timers = (req->cmd == VIRTIO_ACCEL_CMD_DO_OP);
	struct scatterlist hdr_sg;
	struct scatterlist out_hdr_sg;
	struct scatterlist in_hdr_sg;
	struct scatterlist status_sg;
	struct scatterlist sid_sg;
	struct scatterlist ret_sg;
	struct scatterlist **sgs;
	int out_nsgs = 0;
	int in_nsgs = 0;
	int ret;

	/* Start with required SGs [hdr + ret + status (+ sid)] */
	int total_sgs = has_sess_id ? 4 : 3;

	struct virtio_accel_session *sess =
		has_timers ?
			virtio_accel_session_get_by_id(vacl, u_op->session_id) :
			NULL;

	virtio_accel_profiler_timer_start(sess,
					  "request submit > prepare request");
	ret = prepare_request_with_args(req, op_req, vdev);
	if (ret < 0) {
		vacl_err("Failed to parse user args\n");
		return ret;
	}
	virtio_accel_profiler_timer_stop(sess,
					 "request submit > prepare request");

	virtio_accel_profiler_timer_start(sess,
					  "request submit > create sg lists");
	total_sgs += ret;

	sgs = kzalloc_node(total_sgs * sizeof(*sgs), GFP_ATOMIC,
			   dev_to_node(&vdev->dev));
	if (!sgs) {
		ret = -ENOMEM;
		goto free_request;
	}

	/* header */
	ret = sg_add_buf(&sgs[out_nsgs++], &hdr_sg, h, sizeof(*h));
	if (ret < 0)
		goto free_sgs;

	/* user out arguments */
	ret = sg_add_args(&sgs[out_nsgs], &out_hdr_sg, &req->sg_allocs,
			  req->arg_hdrs.out, op_req->op.out_bufs, u_op->nr_out,
			  vdev);
	if (ret < 0) {
		vacl_err("Failed to add user read args\n");
		goto free_sgs;
	}

	out_nsgs += ret;

	/* user in arguments */
	ret = sg_add_args(&sgs[out_nsgs + in_nsgs], &in_hdr_sg, &req->sg_allocs,
			  req->arg_hdrs.in, op_req->op.in_bufs, u_op->nr_in,
			  vdev);
	if (ret < 0) {
		vacl_err("Failed to add user write args\n");
		goto free_sg_allocs;
	}

	in_nsgs += ret;

	if (has_sess_id) {
		/* session id */
		ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &sid_sg,
				 &u_op->session_id, sizeof(u_op->session_id));
		if (ret < 0)
			goto free_sg_allocs;
	}

	/* operation return value */
	ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &ret_sg, &u_op->ret,
			 sizeof(u_op->ret));
	if (ret < 0)
		goto free_sg_allocs;

	/* result status */
	ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &status_sg, &req->status,
			 sizeof(req->status));
	if (ret < 0)
		goto free_sg_allocs;

	req->sgs = sgs;
	req->nr_out_sgs = out_nsgs;
	req->nr_in_sgs = in_nsgs;
	virtio_accel_profiler_timer_stop(sess,
					 "request submit > create sg lists");

	virtio_accel_profiler_timer_start(sess, "request submit > commit");
	ret = virtio_accel_request_commit(req);
	virtio_accel_profiler_timer_stop(sess, "request submit > commit");

	return ret;

free_sg_allocs:
	for (unsigned int i = 0; i < req->sg_allocs.count; i++)
		kfree(req->sg_allocs.allocs[i]);
	kfree(req->sg_allocs.allocs);
free_sgs:
	kfree(sgs);
	req->sgs = NULL;
free_request:
	kfree_sensitive(req->arg_hdrs.out);
	kfree_sensitive(req->arg_hdrs.in);
	h->op.nr_out = 0;
	h->op.nr_in = 0;

	complete_all(&req->completion);
	return ret;
}

static int submit_req_with_timers(struct virtio_accel_request *req)
{
	struct virtio_accel *vacl = req->vacl;
	struct virtio_device *vdev = vacl->vdev;
	struct virtio_accel_header *h = &req->hdr;
	struct virtio_accel_op_request *op_req = req->op_req;
	struct virtio_accel_profiler_op *u_op = &op_req->profiler_op.u_op;
	struct scatterlist hdr_sg;
	struct scatterlist nr_regions_sg;
	struct scatterlist region_hdrs_sg;
	struct scatterlist sample_hdrs_sg;
	struct scatterlist ret_sg;
	struct scatterlist status_sg;
	struct scatterlist **sgs;
	unsigned int region_hdrs_size;
	unsigned int sample_hdrs_size;
	int out_nsgs = 0;
	int in_nsgs = 0;
	int ret;

	/* Start with required SGs [hdr + region count + ret + status */
	int total_sgs = 4;

	ret = prepare_request_with_timers(req, op_req, vdev, &region_hdrs_size,
					  &sample_hdrs_size);
	if (ret < 0) {
		vacl_err("Failed to parse user regions: %d\n", ret);
		return ret;
	}

	if (u_op->max_regions && ret == 0) {
		/* If only kernel timers fit, there is no need for a VirtIO
		 * call */
		complete_all(&req->completion);
		return 0;
	}

	total_sgs += ret;

	sgs = kzalloc_node(total_sgs * sizeof(*sgs), GFP_ATOMIC,
			   dev_to_node(&vdev->dev));
	if (!sgs) {
		ret = -ENOMEM;
		goto err_free_req;
	}

	/* header */
	ret = sg_add_buf(&sgs[out_nsgs++], &hdr_sg, h, sizeof(*h));
	if (ret < 0)
		goto err_free_sgs;

	if (u_op->max_regions) {
		/* user regions */
		ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &region_hdrs_sg,
				 req->timer_hdrs.regions, region_hdrs_size);
		if (ret < 0) {
			vacl_err("Failed to add user regions\n");
			goto err_free_sgs;
		}

		/* user samples */
		ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &sample_hdrs_sg,
				 req->timer_hdrs.samples, sample_hdrs_size);
		if (ret < 0) {
			vacl_err("Failed to add user samples\n");
			goto err_free_sgs;
		}
	}

	/* vmm region count */
	ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &nr_regions_sg,
			 &u_op->nr_regions, sizeof(u_op->nr_regions));
	if (ret < 0)
		goto err_free_sgs;

	/* operation return value */
	ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &ret_sg, &u_op->ret,
			 sizeof(u_op->ret));
	if (ret < 0)
		goto err_free_sgs;

	/* result status */
	ret = sg_add_buf(&sgs[out_nsgs + in_nsgs++], &status_sg, &req->status,
			 sizeof(req->status));
	if (ret < 0)
		goto err_free_sgs;

	req->sgs = sgs;
	req->nr_out_sgs = out_nsgs;
	req->nr_in_sgs = in_nsgs;

	return virtio_accel_request_commit(req);

err_free_sgs:
	kfree(sgs);
	req->sgs = NULL;
err_free_req:
	kfree(req->timer_hdrs.regions);
	kfree(req->timer_hdrs.samples);
	h->op.nr_out = 0;
	h->op.nr_in = 0;

	complete_all(&req->completion);
	return ret;
}

int virtio_accel_request_submit(struct virtio_accel_request *req)
{
	if (unlikely(!req))
		return -EINVAL;

	if (req->cmd == VIRTIO_ACCEL_CMD_GET_TIMERS)
		return submit_req_with_timers(req);

	return submit_req_with_args(req);
}

static void handle_req_result_with_args(struct virtio_accel_request *req)
{
	struct virtio_accel *vacl = req->vacl;
	struct virtio_device *vdev = vacl->vdev;
	struct virtio_accel_op_request *op_req = req->op_req;
	struct virtio_accel_op *u_op = &op_req->op.u_op;

	if (req->status != VIRTIO_ACCEL_OK) {
		u_op->ret = virtio32_to_cpu(vdev, u_op->ret);
		return;
	}

	switch (req->cmd) {
	case VIRTIO_ACCEL_CMD_CREATE_SESSION:
		u_op->session_id = virtio64_to_cpu(vdev, u_op->session_id);
		if (!u_op->session_id)
			break;

		if (!virtio_accel_session_create_and_add(vacl,
							 u_op->session_id)) {
			req->ret = -ENOMEM;
			break;
		}
		break;
	case VIRTIO_ACCEL_CMD_DESTROY_SESSION:
		virtio_accel_session_delete(vacl, u_op->session_id);
		break;
	case VIRTIO_ACCEL_CMD_DO_OP:
		break;
	default:
		req->ret = -EBADMSG;
		break;
	}

	if (req->ret < 0)
		return;

	for (unsigned int i = 0; i < u_op->nr_in; i++) {
		op_req->op.in[i].len =
			virtio32_to_cpu(vdev, req->arg_hdrs.in[i].len);
		op_req->op.in[i].type =
			virtio32_to_cpu(vdev, req->arg_hdrs.in[i].type);
		op_req->op.in[i].custom_type_id = virtio32_to_cpu(
			vdev, req->arg_hdrs.in[i].custom_type_id);
	}
}

static void handle_req_result_with_timers(struct virtio_accel_request *req)
{
	struct virtio_accel *vacl = req->vacl;
	struct virtio_device *vdev = vacl->vdev;
	struct virtio_accel_op_request *op_req = req->op_req;
	struct virtio_accel_profiler_op *u_op = &op_req->profiler_op.u_op;
	struct virtio_accel_profiler_region *regions =
		op_req->profiler_op.regions;
	unsigned int nr_k_regions;
	unsigned int nr_v_regions;
	unsigned int s_pos = 0;
	unsigned int i;
	unsigned int j;

	if (req->status != VIRTIO_ACCEL_OK) {
		u_op->ret = virtio32_to_cpu(vdev, u_op->ret);
		return;
	}

	struct virtio_accel_session *sess =
		virtio_accel_session_get_by_id(vacl, u_op->session_id);
	if (!sess) {
		req->ret = -EBADMSG;
		return;
	}

	nr_v_regions = virtio32_to_cpu(vdev, u_op->nr_regions);
	u_op->nr_regions = 0;

	/* If max_regions == 0, return the region count so the user can
	 * allocate */
	if (u_op->max_regions == 0) {
		u_op->nr_regions = nr_v_regions + (u32)sess->nr_timers;
		return;
	}

	/* First add kernel regions */
	nr_k_regions = virtio_accel_profiler_get_regions(
		sess, regions, op_req->profiler_op.samples_bufs,
		u_op->max_regions);
	if (sess->nr_timers && sess->nr_timers <= u_op->max_regions &&
	    sess->nr_timers != nr_k_regions) {
		/* If all kernel timers fit and we did not get them all, error
		 * out */
		req->ret = -EINVAL;
		return;
	}

	/* Add VMM regions */
	for (i = nr_k_regions; i < u_op->max_regions; i++) {
		unsigned int r_pos = i - nr_k_regions;
		struct virtio_accel_profiler_sample *samples;

		if (i == nr_k_regions + nr_v_regions)
			break;

		samples = (struct virtio_accel_profiler_sample *)
			virtio_accel_buffer_get_mapped(
				&op_req->profiler_op.samples_bufs[i]);
		if (!samples) {
			req->ret = -EINVAL;
			return;
		}

		strscpy(regions[i].name, req->timer_hdrs.regions[r_pos].name,
			VIRTIO_ACCEL_TIMERS_NAME_MAX);

		regions[i].nr_samples = virtio32_to_cpu(
			vdev, req->timer_hdrs.regions[r_pos].nr_samples);
		for (j = 0; j < regions[i].nr_samples; j++) {
			samples[j].start = virtio64_to_cpu(
				vdev, req->timer_hdrs.samples[s_pos + j].start);
			samples[j].time = virtio64_to_cpu(
				vdev, req->timer_hdrs.samples[s_pos + j].time);
		}
		s_pos += regions[i].max_samples;
	}

	u_op->nr_regions = i;
}

void virtio_accel_request_handle_result(struct virtio_accel_request *req)
{
	if (!req)
		return;

	if (req->cmd == VIRTIO_ACCEL_CMD_GET_TIMERS)
		return handle_req_result_with_timers(req);

	return handle_req_result_with_args(req);
}

static uint64_t generate_request_id(struct virtio_accel *vacl)
{
	return atomic64_fetch_inc(&vacl->next_request_id);
}

static int commit_single_req(struct virtio_accel_request *req)
{
	struct virtio_accel *vacl = req->vacl;
	int ret;
	unsigned long flags;

	// Select vq[0] explicitly for now
	spin_lock_irqsave(&vacl->vqs[0].lock, flags);
	ret = virtqueue_add_sgs(vacl->vqs[0].vq, req->sgs, req->nr_out_sgs,
				req->nr_in_sgs, req, GFP_ATOMIC);
	if (unlikely(ret < 0)) {
		spin_unlock_irqrestore(&vacl->vqs[0].lock, flags);
		complete_all(&req->completion);
		return ret;
	}

	virtqueue_kick(vacl->vqs[0].vq);
	spin_unlock_irqrestore(&vacl->vqs[0].lock, flags);

	return -EINPROGRESS;
}

static unsigned int count_total_sgs(struct virtio_accel_request *req)
{
	unsigned int i;
	unsigned int total = 0;

	for (i = 0; i < req->nr_out_sgs; i++)
		total += sg_nents(req->sgs[i]);

	for (i = 0; i < req->nr_in_sgs; i++)
		total += sg_nents(req->sgs[req->nr_out_sgs + i]);

	return total;
}

static struct scatterlist *create_sg_subchain(struct scatterlist *orig_chain,
					      unsigned int start_idx,
					      unsigned int count)
{
	struct scatterlist *new_chain, *sg;
	unsigned int i, idx = 0;

	if (count == 0)
		return NULL;

	new_chain = kcalloc(count, sizeof(struct scatterlist), GFP_KERNEL);
	if (!new_chain)
		return NULL;

	sg_init_table(new_chain, count);

	// Walk original chain to find entries to copy
	for_each_sg(orig_chain, sg, sg_nents(orig_chain), i)
	{
		if (i >= start_idx && idx < count) {
			sg_set_page(&new_chain[idx], sg_page(sg), sg->length,
				    sg->offset);
			idx++;
			if (idx >= count)
				break;
		}
	}

	// Mark the last entry in the new chain
	if (idx > 0)
		sg_mark_end(&new_chain[idx - 1]);

	return new_chain;
}

static int collect_chunk_sgs(struct scatterlist **sgs, unsigned int nr_out_sgs,
			     unsigned int nr_in_sgs, unsigned int sg_offset,
			     unsigned int chunk_sg_total_count,
			     unsigned int chunk_sg_count,
			     struct scatterlist **chunk_sgs,
			     unsigned int *chunk_sg_col_total_count,
			     unsigned int *chunk_nr_out_sgs,
			     unsigned int *chunk_nr_in_sgs,
			     struct virtio_accel_sg_allocs *chunk_sg_allocs)
{
	unsigned int curr_sg_idx = 0;
	unsigned int chunk_sg_idx = 0;
	unsigned int collect_sg_total_count = 0;
	unsigned int collect_nr_out_sgs = 0;
	unsigned int collect_nr_in_sgs = 0;
	unsigned int sg_count = nr_out_sgs + nr_in_sgs;
	unsigned int ent_idx;
	struct virtio_accel_sg_allocs *sg_allocs =
		chunk_sg_allocs ? chunk_sg_allocs : NULL;
	bool count_only = (chunk_sgs == NULL);
	int ret;

	if (!count_only && sg_allocs) {
		sg_allocs->allocs = kcalloc(
			chunk_sg_count, sizeof(*sg_allocs->allocs), GFP_KERNEL);
		if (!sg_allocs->allocs)
			return -ENOMEM;

		sg_allocs->capacity = chunk_sg_count;
	}

	for (ent_idx = 0; ent_idx < sg_count &&
			  collect_sg_total_count < chunk_sg_total_count;
	     ent_idx++) {
		struct scatterlist *ent_sg_chain = sgs[ent_idx];
		unsigned int ent_sg_total_count =
			ent_sg_chain ? sg_nents(ent_sg_chain) : 0;
		unsigned int ent_start = curr_sg_idx;
		unsigned int ent_end = curr_sg_idx + ent_sg_total_count - 1;
		unsigned int chunk_start = sg_offset;
		unsigned int chunk_end = sg_offset + chunk_sg_total_count;

		// This entry overlaps with our chunk
		unsigned int ent_chunk_offset =
			max(ent_start, chunk_start) - ent_start;
		unsigned int ent_collect_sgs =
			min(ent_sg_total_count - ent_chunk_offset,
			    chunk_sg_total_count - collect_sg_total_count);

		if (!ent_sg_chain)
			continue;

		vacl_debug("Processing SG entry %u with %u chained entries\n",
			   ent_idx, ent_sg_total_count);

		if (ent_end < chunk_start) {
			// This entire entry is before our chunk
			curr_sg_idx += ent_sg_total_count;
			continue;
		}

		if (ent_start >= chunk_end) {
			// This entry starts after our chunk
			break;
		}

		if (!count_only) {
			vacl_debug(
				"  Taking %u SGs from entry %u (starting at offset %u)\n",
				ent_collect_sgs, ent_idx, ent_chunk_offset);

			if (ent_collect_sgs == ent_sg_total_count &&
			    ent_chunk_offset == 0) {
				// Take the entire argument chain as-is
				chunk_sgs[chunk_sg_idx] = ent_sg_chain;
				vacl_debug("  Using complete entry chain\n");
			} else {
				// Create a new sub-chain
				struct scatterlist *new_chain =
					create_sg_subchain(ent_sg_chain,
							   ent_chunk_offset,
							   ent_collect_sgs);
				if (!new_chain) {
					vacl_err(
						"Failed to create sub-chain\n");
					ret = -ENOMEM;
					goto free_sg_allocs;
				}

				chunk_sgs[chunk_sg_idx] = new_chain;
				if (sg_allocs) {
					if (sg_allocs->count ==
					    sg_allocs->capacity) {
						vacl_err(
							"Failed to store SG allocations\n");
						ret = -EINVAL;
						goto free_sg_allocs;
					}
					sg_allocs->allocs[sg_allocs->count++] =
						new_chain;
				}
				vacl_debug(
					"  Created new sub-chain with %u entries\n",
					ent_collect_sgs);
			}
		}

		chunk_sg_idx++;
		collect_sg_total_count += ent_collect_sgs;

		if (ent_idx < nr_out_sgs)
			collect_nr_out_sgs++;
		else
			collect_nr_in_sgs++;

		curr_sg_idx += ent_sg_total_count;

		if (collect_sg_total_count >= chunk_sg_total_count)
			break;
	}

	if (chunk_nr_out_sgs)
		*chunk_nr_out_sgs = collect_nr_out_sgs;
	if (chunk_nr_in_sgs)
		*chunk_nr_in_sgs = collect_nr_in_sgs;
	if (chunk_sg_col_total_count)
		*chunk_sg_col_total_count = collect_sg_total_count;

	if (!count_only) {
		vacl_debug(
			"Collected %u data SGs/SG chains (%u out, %u in), %u total data SGs\n",
			chunk_sg_idx, collect_nr_out_sgs, collect_nr_in_sgs,
			collect_sg_total_count);
	}

	return (int)chunk_sg_idx;

free_sg_allocs:
	if (sg_allocs) {
		for (unsigned int i = 0; i < sg_allocs->count; i++)
			kfree(sg_allocs->allocs[i]);

		kfree(sg_allocs->allocs);
		sg_allocs->count = 0;
		sg_allocs->capacity = 0;
	}

	return ret;
}

static int create_chunk_request(struct virtio_accel_request *parent,
				unsigned int chunk_sg_max_count,
				unsigned int sg_data_offset,
				unsigned int sg_total_count,
				struct virtio_accel_request **chunk_req)
{
	unsigned int chunk_sg_data_total_count = min(
		chunk_sg_max_count - 2, sg_total_count - 1 - sg_data_offset);
	unsigned int sg_count = parent->nr_out_sgs + parent->nr_in_sgs;
	int chunk_sg_data_count;
	unsigned int chunk_sg_count;
	int collect_sg_count;
	unsigned int collect_sg_total_count;
	struct scatterlist **chunk_sgs;
	struct virtio_accel_request *chunk;
	int ret;

	chunk = virtio_accel_request_new_with_parent(parent);
	if (!chunk)
		return -ENOMEM;

	// Calculate chunk data SG count
	chunk_sg_data_count = collect_chunk_sgs(
		&parent->sgs[1], parent->nr_out_sgs - 1, parent->nr_in_sgs - 1,
		sg_data_offset, chunk_sg_data_total_count, 0, NULL, NULL, NULL,
		NULL, NULL);
	if (chunk_sg_data_count < 0)
		return chunk_sg_data_count;

	chunk_sg_count = chunk_sg_data_count + 2;
	chunk_sgs = kcalloc(chunk_sg_count, sizeof(*chunk_sgs), GFP_KERNEL);
	if (!chunk_sgs) {
		ret = -ENOMEM;
		goto free_chunk;
	}

	vacl_debug("Creating chunk: data_offset=%u, count=%u\n", sg_data_offset,
		   chunk_sg_count);

	// Create data SG subset for this chunk
	collect_sg_count = collect_chunk_sgs(
		&parent->sgs[1], parent->nr_out_sgs - 1, parent->nr_in_sgs - 1,
		sg_data_offset, chunk_sg_data_total_count, chunk_sg_data_count,
		&chunk_sgs[1], &collect_sg_total_count, &chunk->nr_out_sgs,
		&chunk->nr_in_sgs, &chunk->sg_allocs);
	if (collect_sg_count < 0) {
		ret = collect_sg_count;
		goto free_chunk_sgs;
	}

	if (collect_sg_count != chunk_sg_data_count) {
		ret = -EINVAL;
		goto free_chunk_sgs;
	}

	// First entry is always the header (shared across all chunks)
	chunk_sgs[0] = parent->sgs[0];
	chunk->nr_out_sgs++;

	// Last entry is always the status (shared across all chunks)
	chunk_sgs[collect_sg_count + 1] = parent->sgs[sg_count - 1];
	chunk->nr_in_sgs++;

	chunk->sgs = chunk_sgs;
	*chunk_req = chunk;

	vacl_debug("Chunk created with out_sgs=%u, in_sgs=%u\n",
		   chunk->nr_out_sgs, chunk->nr_in_sgs);

	return (int)collect_sg_total_count;

free_chunk_sgs:
	kfree(chunk_sgs);
free_chunk:
	kfree(chunk);
	return ret;
}

static unsigned int calculate_sg_chunks(unsigned int sg_total_count,
					unsigned int chunk_sg_max_count)
{
	unsigned int sg_total_data_count =
		sg_total_count - 2; // exclude header + status
	unsigned int chunk_sg_max_data_count =
		chunk_sg_max_count - 2; // add per-chunk header + status

	return DIV_ROUND_UP(sg_total_data_count, chunk_sg_max_data_count);
}

static int commit_chunked_req(struct virtio_accel_request *parent_req)
{
	struct virtio_accel *vacl = parent_req->vacl;
	unsigned int sg_total_count = count_total_sgs(parent_req);
	unsigned int total_chunks =
		calculate_sg_chunks(sg_total_count, vacl->max_req_descriptors);
	unsigned int sg_data_offset = 0;
	int ret;

	parent_req->hdr.request_id = generate_request_id(vacl);
	parent_req->hdr.total_chunks = total_chunks;
	atomic_set(&parent_req->chunk_count, total_chunks);

	for (unsigned int i = 0; i < total_chunks; i++) {
		struct virtio_accel_request *chunk_req;

		int sg_collect_count = create_chunk_request(
			parent_req, vacl->max_req_descriptors, sg_data_offset,
			sg_total_count, &chunk_req);
		if (sg_collect_count < 0)
			return sg_collect_count;

		vacl_debug("Submitting chunk %u for request id %llu\n", i,
			   chunk_req->hdr.request_id);

		ret = commit_single_req(chunk_req);
		if (ret != -EINPROGRESS)
			return ret;

		sg_data_offset += (unsigned int)sg_collect_count;
	}

	return -EINPROGRESS;
}

int virtio_accel_request_commit(struct virtio_accel_request *req)
{
	struct virtio_accel *vacl = req->vacl;
	unsigned int sg_total_count = count_total_sgs(req);

	if (sg_total_count <= vacl->max_req_descriptors)
		return commit_single_req(req);

	return commit_chunked_req(req);
}
