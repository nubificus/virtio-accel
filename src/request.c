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

static int prepare_arg_headers(struct virtio_accel_arg_header **arg_hdrs,
			       struct virtio_accel_arg *args, u32 nr_args,
			       bool write, struct virtio_device *vdev)
{
	struct virtio_accel_arg_header *hdrs;
	int i;

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

static int prepare_request(struct virtio_accel_request *req,
			   struct virtio_accel_op_request *op_req, u32 cmd,
			   struct virtio_device *vdev)
{
	struct virtio_accel_header *h = &req->hdr;
	struct virtio_accel_op *u_op = &op_req->u_op;
	int ret;
	int total_sgs = 0;

	if (!req || !op_req)
		return -EINVAL;

	vacl_debug(
		"Request session_id=%llu, cmd=%u, op_code=%u, nr_out=%u, nr_in=%u\n",
		u_op->session_id, cmd, u_op->op_code, u_op->nr_out,
		u_op->nr_in);

	h->session_id = cpu_to_virtio32(vdev, u_op->session_id);
	h->cmd = cpu_to_virtio32(vdev, cmd);
	h->op_code = cpu_to_virtio32(vdev, u_op->op_code);

	ret = prepare_arg_headers(&req->out_hdrs, op_req->out, u_op->nr_out, 0,
				  vdev);
	if (ret < 0)
		return ret;

	total_sgs += ret + 1;
	h->nr_out = cpu_to_virtio32(vdev, u_op->nr_out);

	ret = prepare_arg_headers(&req->in_hdrs, op_req->in, u_op->nr_in, 1,
				  vdev);
	if (ret < 0)
		goto free_out;

	total_sgs += ret + 1;
	h->nr_in = cpu_to_virtio32(vdev, u_op->nr_in);

	if ((op_req->out_bufs && !op_req->out_bufs[0].pinned) ||
	    (op_req->in_bufs && !op_req->in_bufs[0].pinned)) {
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
	kfree_sensitive(req->out_hdrs);
	h->nr_out = 0;

	return ret;
}

static int sg_add_buf(struct scatterlist **sgs, struct scatterlist *sg,
		      void *buf, u32 size)
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

struct virtio_accel_request *
virtio_accel_request_new(struct virtio_accel *vacl,
			 struct virtio_accel_op_request *op_req)
{
	struct virtio_accel_request *req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->vacl = vacl;
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

	kfree_sensitive(req->out_hdrs);
	kfree_sensitive(req->in_hdrs);

	for (unsigned int i = 0; i < req->sg_allocs.count; i++)
		kfree(req->sg_allocs.allocs[i]);

	kfree(req->sg_allocs.allocs);
	kfree(req->sgs);
	kfree(req);
}

int virtio_accel_request_submit(struct virtio_accel_request *req, u32 cmd)
{
	struct scatterlist hdr_sg;
	struct scatterlist out_hdr_sg;
	struct scatterlist in_hdr_sg;
	struct scatterlist status_sg;
	struct scatterlist sid_sg;
	struct scatterlist ret_sg;
	struct scatterlist **sgs;
	struct virtio_accel *vacl = req->vacl;
	struct virtio_device *vdev = vacl->vdev;
	struct virtio_accel_header *h = &req->hdr;
	struct virtio_accel_op_request *op_req = req->op_req;
	struct virtio_accel_op *u_op = &op_req->u_op;
	int ret;
	int out_nsgs = 0;
	int in_nsgs = 0;

	// Start with required SGs [hdr + ret + status (+ sid)]
	int total_sgs = (cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) ? 4 : 3;

	struct virtio_accel_session *sess =
		(cmd == VIRTIO_ACCEL_CMD_DO_OP) ?
			virtio_accel_session_get_by_id(u_op->session_id, req) :
			NULL;

	virtio_accel_profiler_timer_start(sess,
					  "request submit > prepare request");
	ret = prepare_request(req, op_req, cmd, vdev);
	if (ret < 0) {
		vacl_err("Failed to parse user arguments: %d\n", ret);
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
			  req->out_hdrs, op_req->out_bufs, h->nr_out, vdev);
	if (ret < 0) {
		vacl_err("Failed to add user read arguments: %d\n", ret);
		goto free_sgs;
	}

	out_nsgs += ret;

	/* user in arguments */
	ret = sg_add_args(&sgs[out_nsgs + in_nsgs], &in_hdr_sg, &req->sg_allocs,
			  req->in_hdrs, op_req->in_bufs, h->nr_in, vdev);
	if (ret < 0) {
		vacl_err("Failed to add user write arguments: %d\n", ret);
		goto free_sg_allocs;
	}

	in_nsgs += ret;

	if (cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) {
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
	req->out_sgs = out_nsgs;
	req->in_sgs = in_nsgs;
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
	kfree_sensitive(req->out_hdrs);
	kfree_sensitive(req->in_hdrs);
	h->nr_out = 0;
	h->nr_in = 0;

	complete_all(&req->completion);
	return ret;
}

static int virtio_accel_handle_timers(struct virtio_accel_request *req)
{
	struct virtio_accel_header *h = &req->hdr;
	struct virtio_accel_op_request *op_req = req->op_req;
	struct virtio_accel_profiler_region *regions;
	struct virtio_accel_profiler_sample **tmp_samples;
	int ret;
	int *nt;
	int *qnt;
	int i;
	int nr_regions;

	struct virtio_accel_session *sess =
		virtio_accel_session_get_by_id(op_req->u_op.session_id, req);

	nt = (int *)virtio_accel_buffer_map(&op_req->in_bufs[0]);
	if (!nt)
		return -ENOMEM;

	if (*nt == 0) {
		*nt = (int)sess->nr_timers;
		return 0;
	}

	qnt = (int *)virtio_accel_buffer_map(&op_req->in_bufs[1]);
	if (!qnt)
		return -ENOMEM;

	nr_regions = (*nt) + (*qnt);
	if (h->nr_in < 3 + nr_regions)
		return -EINVAL;

	regions =
		(struct virtio_accel_profiler_region *)virtio_accel_buffer_map(
			&op_req->in_bufs[2]);
	if (!regions)
		return -ENOMEM;

	if (req->in_hdrs[2].len < nr_regions * sizeof(*regions))
		return -EINVAL;

	tmp_samples =
		kmalloc_array(nr_regions, sizeof(*tmp_samples), GFP_KERNEL);
	if (!tmp_samples)
		return -ENOMEM;

	for (i = 0; i < nr_regions; i++) {
		tmp_samples[i] = regions[i].samples;
		regions[i].samples = (struct virtio_accel_profiler_sample *)
			virtio_accel_buffer_map(&op_req->in_bufs[3 + i]);
		if (!regions[i].samples) {
			ret = -ENOMEM;
			goto free_samples;
		}
	}

	ret = (int)virtio_accel_profiler_get_regions(sess, regions, nr_regions);

free_samples:
	while (i--)
		regions[i].samples = tmp_samples[i];

	kfree(tmp_samples);
	return ret;
}

void virtio_accel_request_handle_result(struct virtio_accel_request *req)
{
	struct virtio_accel *vacl = req->vacl;
	struct virtio_device *vdev = vacl->vdev;
	struct virtio_accel_header *h = &req->hdr;
	struct virtio_accel_op_request *op_req = req->op_req;
	struct virtio_accel_op *u_op = &op_req->u_op;
	int ret;

	if (req->status != VIRTIO_ACCEL_OK) {
		u_op->ret = virtio32_to_cpu(vdev, u_op->ret);
		return;
	}

	switch (virtio32_to_cpu(vdev, h->cmd)) {
	case VIRTIO_ACCEL_CMD_CREATE_SESSION:
		u_op->session_id = virtio64_to_cpu(vdev, u_op->session_id);
		if (!u_op->session_id)
			break;

		if (!virtio_accel_session_create_and_add(u_op->session_id,
							 req)) {
			req->ret = -ENOMEM;
			break;
		}
		break;
	case VIRTIO_ACCEL_CMD_DESTROY_SESSION:
		virtio_accel_session_delete(u_op->session_id, req);
		break;
	case VIRTIO_ACCEL_CMD_DO_OP:
		break;
	case VIRTIO_ACCEL_CMD_GET_TIMERS:
		ret = virtio_accel_handle_timers(req);
		if (ret < 0)
			req->ret = ret;
		break;
	default:
		req->ret = -EBADMSG;
		break;
	}

	if (req->ret < 0 || !u_op->nr_in)
		return;

	for (u32 i = 0; i < u_op->nr_in; i++) {
		op_req->in[i].len = virtio32_to_cpu(vdev, req->in_hdrs[i].len);
		op_req->in[i].type =
			virtio32_to_cpu(vdev, req->in_hdrs[i].type);
		op_req->in[i].custom_type_id =
			virtio32_to_cpu(vdev, req->in_hdrs[i].custom_type_id);
	}
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
	ret = virtqueue_add_sgs(vacl->vqs[0].vq, req->sgs, req->out_sgs,
				req->in_sgs, req, GFP_ATOMIC);
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

	for (i = 0; i < req->out_sgs; i++)
		total += sg_nents(req->sgs[i]);

	for (i = 0; i < req->in_sgs; i++)
		total += sg_nents(req->sgs[req->out_sgs + i]);

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

static int collect_chunk_sgs(struct scatterlist **sgs, unsigned int out_sgs,
			     unsigned int in_sgs, unsigned int sg_offset,
			     unsigned int chunk_sg_total_count,
			     unsigned int chunk_sg_count,
			     struct scatterlist **chunk_sgs,
			     unsigned int *chunk_sg_col_total_count,
			     unsigned int *chunk_out_sgs,
			     unsigned int *chunk_in_sgs,
			     struct virtio_accel_sg_allocs *chunk_sg_allocs)
{
	unsigned int curr_sg_idx = 0;
	unsigned int chunk_sg_idx = 0;
	unsigned int collect_sg_total_count = 0;
	unsigned int collect_out_sgs = 0;
	unsigned int collect_in_sgs = 0;
	unsigned int sg_count = out_sgs + in_sgs;
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

		if (ent_idx < out_sgs)
			collect_out_sgs++;
		else
			collect_in_sgs++;

		curr_sg_idx += ent_sg_total_count;

		if (collect_sg_total_count >= chunk_sg_total_count)
			break;
	}

	if (chunk_out_sgs)
		*chunk_out_sgs = collect_out_sgs;
	if (chunk_in_sgs)
		*chunk_in_sgs = collect_in_sgs;
	if (chunk_sg_col_total_count)
		*chunk_sg_col_total_count = collect_sg_total_count;

	if (!count_only) {
		vacl_debug(
			"Collected %u data SGs/SG chains (%u out, %u in), %u total data SGs\n",
			chunk_sg_idx, collect_out_sgs, collect_in_sgs,
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
	unsigned int sg_count = parent->out_sgs + parent->in_sgs;
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
		&parent->sgs[1], parent->out_sgs - 1, parent->in_sgs - 1,
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
		&parent->sgs[1], parent->out_sgs - 1, parent->in_sgs - 1,
		sg_data_offset, chunk_sg_data_total_count, chunk_sg_data_count,
		&chunk_sgs[1], &collect_sg_total_count, &chunk->out_sgs,
		&chunk->in_sgs, &chunk->sg_allocs);
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
	chunk->out_sgs++;

	// Last entry is always the status (shared across all chunks)
	chunk_sgs[collect_sg_count + 1] = parent->sgs[sg_count - 1];
	chunk->in_sgs++;

	chunk->sgs = chunk_sgs;
	*chunk_req = chunk;

	vacl_debug("Chunk created with out_sgs=%u, in_sgs=%u\n", chunk->out_sgs,
		   chunk->in_sgs);

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
