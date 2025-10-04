// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "accel-internal.h"
#include "virtio_accel-common.h"
#include "virtio_accel-prof.h"

static int virtaccel_prepare_args(struct virtio_accel_arg_hdr **arg_hdrs,
				  struct accel_arg *args, u32 nr_args,
				  bool write, struct virtio_device *vdev)
{
	struct virtio_accel_arg_hdr *hdrs;
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
	return nr_args;
}

static int virtaccel_prepare_request(struct virtio_device *vdev, u32 cmd,
				     struct virtio_accel_req *req,
				     struct accel_op_req *op_req)
{
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op *u_op = &op_req->u_op;
	int ret;
	int total_sgs = 0;

	virtaccel_debug(
		"Request session_id=%llu, cmd=%u, op_code=%u, out_nr=%u, in_nr=%u\n",
		u_op->session_id, cmd, u_op->op_code, u_op->out_nr,
		u_op->in_nr);

	h->session_id = cpu_to_virtio32(vdev, u_op->session_id);
	h->cmd = cpu_to_virtio32(vdev, cmd);
	h->op_code = cpu_to_virtio32(vdev, u_op->op_code);

	ret = virtaccel_prepare_args(&req->out_arg_hdrs, op_req->out,
				     u_op->out_nr, 0, vdev);
	if (ret < 0)
		return ret;

	total_sgs += ret + 1;
	h->out_nr = cpu_to_virtio32(vdev, u_op->out_nr);

	ret = virtaccel_prepare_args(&req->in_arg_hdrs, op_req->in, u_op->in_nr,
				     1, vdev);
	if (ret < 0)
		goto free_out;

	total_sgs += ret + 1;
	h->in_nr = cpu_to_virtio32(vdev, u_op->in_nr);

	return total_sgs;

free_out:
	kfree_sensitive(req->out_arg_hdrs);
	h->out_nr = 0;

	return ret;
}

static int sg_add_vaccel_one(struct scatterlist **sgs, struct scatterlist *sg,
			     void *ptr, u32 size)
{
	if (!sgs || !ptr || !size)
		return -EINVAL;

	sg_init_one(sg, ptr, size);
	*sgs = sg;

	return 1;
}

#ifndef ZC

static int sg_add_vaccel_args(struct scatterlist **sgs,
			      struct scatterlist *hdr_sg,
			      struct virtio_accel_arg_hdr *arg_hdrs,
			      struct accel_buf *arg_bufs, u32 nr_args,
			      struct virtio_device *vdev)
{
	struct scatterlist *sg;
	int i;
	int ret;

	if (!sgs || !hdr_sg || (nr_args && (!arg_hdrs || !arg_bufs)) || !vdev)
		return -EINVAL;

	if (!nr_args)
		return 0;

	sg = kmalloc_array_node(nr_args, sizeof(*sg), GFP_KERNEL,
				dev_to_node(&vdev->dev));
	if (!sg)
		return -ENOMEM;

	ret = sg_add_vaccel_one(&sgs[0], hdr_sg, arg_hdrs,
				nr_args * sizeof(*arg_hdrs));
	if (ret < 0) {
		virtaccel_err("Failed to add argument headers\n");
		return ret;
	}

	for (i = 0; i < nr_args; i++) {
		ret = sg_add_vaccel_one(&sgs[i + 1], &sg[i + 1],
					arg_bufs[i].buf, arg_bufs[i].len);
		if (ret < 0) {
			virtaccel_err(
				"Failed to add argument %d buffer (size: %u)\n",
				i, arg_bufs[i].len);
			return ret;
		}
	}

	return i + 1;
}

static void sg_cleanup_vaccel_args(struct scatterlist **sgs)
{
	if (!sgs)
		return;

	kfree(sgs[1]);
}

#else

static int sg_add_vaccel_args(struct scatterlist **sgs,
			      struct scatterlist *hdr_sg,
			      struct virtio_accel_arg_hdr *arg_hdrs,
			      struct accel_buf *arg_bufs, u32 nr_args,
			      struct virtio_device *vdev)
{
	int i;
	int ret;

	if (!sgs || !hdr_sg || (nr_args && (!arg_hdrs || !arg_bufs)) || !vdev)
		return -EINVAL;

	if (!nr_args)
		return 0;

	ret = sg_add_vaccel_one(&sgs[0], hdr_sg, arg_hdrs,
				nr_args * sizeof(*arg_hdrs));
	if (ret < 0) {
		virtaccel_err("Failed to add argument headers\n");
		return ret;
	}

	for (i = 0; i < nr_args; i++) {
		printk(">> len: %u\n", arg_hdrs[i].len);
		sgs[i + 1] = arg_bufs[i].sgt->sgl;
	}

	return i + 1;
}

static void sg_cleanup_vaccel_args(struct scatterlist **sgs)
{
	(void)sgs;
	return;
}

#endif

struct virtio_accel_req *virtaccel_req_new(struct virtio_accel *vaccel,
					   void __user *usr)
{
	struct virtio_accel_req *req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->vaccel = vaccel;
	atomic_set(&req->chunk_count, 0);
	req->usr = usr;

	init_completion(&req->completion);
	return req;
}

struct virtio_accel_req *
virtaccel_req_new_with_parent(struct virtio_accel_req *parent)
{
	struct virtio_accel_req *req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->vaccel = parent->vaccel;
	req->parent = parent;
	atomic_set(&req->chunk_count, 0);
	req->priv = parent->priv;
	req->usr = parent->usr;

	init_completion(&req->completion);
	return req;
}

static void clear_parent(struct virtio_accel_req *req)
{
	if (!req || !req->sgs)
		return;

	if (req->hdr.out_nr)
		sg_cleanup_vaccel_args(&req->sgs[1]);
	if (req->hdr.in_nr)
		sg_cleanup_vaccel_args(&req->sgs[req->out_sgs]);

	kfree_sensitive(req->out_arg_hdrs);
	kfree_sensitive(req->in_arg_hdrs);
}

static void clear_chunk(struct virtio_accel_req *req)
{
	if (!req)
		return;

	for (unsigned int i = 0; i < req->chunk_allocs.count; i++)
		kfree(req->chunk_allocs.chains[i]);
	kfree(req->chunk_allocs.chains);

	atomic_dec(&req->parent->chunk_count);
}

void virtaccel_req_clear(struct virtio_accel_req *req)
{
	if (!req)
		return;

	if (!req->parent) {
		if (!completion_done(&req->completion))
			return;

		clear_parent(req);
	} else {
		clear_chunk(req);
	}

	kfree(req->sgs);

	atomic_set(&req->chunk_count, 0);
	memset(req, 0, sizeof(*req));
}

void virtaccel_req_delete(struct virtio_accel_req *req)
{
	if (!req)
		return;

	if (!req->parent && !completion_done(&req->completion))
		return;

	virtaccel_req_clear(req);
	kfree(req);
}

int virtaccel_req_operation(struct virtio_accel_req *req, u32 cmd)
{
	struct scatterlist hdr_sg;
	struct scatterlist out_hdr_sg;
	struct scatterlist in_hdr_sg;
	struct scatterlist status_sg;
	struct scatterlist sid_sg;
	struct scatterlist ret_sg;
	struct scatterlist **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op_req *op_req = req->priv;
	struct accel_op *u_op = &op_req->u_op;
	int ret;
	int out_nsgs = 0;
	int in_nsgs = 0;

	// Start with required SGs [hdr + ret + status (+ sid)]
	int total_sgs = (cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) ? 4 : 3;

	struct virtio_accel_sess *sess =
		(cmd != VIRTIO_ACCEL_CMD_GET_TIMERS) ?
			virtaccel_session_get_by_id(u_op->session_id, req) :
			NULL;

	virtaccel_timer_start("accel > operation > prepare request", sess);
	ret = virtaccel_prepare_request(vdev, cmd, req, op_req);
	if (ret < 0) {
		virtaccel_err("Failed to parse user arguments: %d\n", ret);
		return ret;
	}
	virtaccel_timer_stop("accel > operation > prepare request", sess);

	virtaccel_timer_start("accel > operation > create sg lists", sess);
	total_sgs += ret;

	sgs = kzalloc_node(total_sgs * sizeof(*sgs), GFP_ATOMIC,
			   dev_to_node(&vdev->dev));
	if (!sgs) {
		ret = -ENOMEM;
		goto free_request;
	}

	/* header */
	ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdr_sg, h, sizeof(*h));
	if (ret < 0)
		goto free_sgs;

	/* user out arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], &out_hdr_sg, req->out_arg_hdrs,
				 op_req->out_bufs, h->out_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user read arguments: %d\n", ret);
		goto free_sgs;
	}

	out_nsgs += ret;

	/* user in arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs + in_nsgs], &in_hdr_sg,
				 req->in_arg_hdrs, op_req->in_bufs, h->in_nr,
				 vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user write arguments: %d\n", ret);
		goto free_out_sg;
	}

	in_nsgs += ret;

	if (cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) {
		/* session id */
		ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &sid_sg,
					&u_op->session_id,
					sizeof(u_op->session_id));
		if (ret < 0)
			goto free_in_sg;
	}

	/* operation return value */
	ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &ret_sg, &u_op->ret,
				sizeof(u_op->ret));
	if (ret < 0)
		goto free_in_sg;

	/* result status */
	ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &status_sg,
				&req->status, sizeof(req->status));
	if (ret < 0)
		goto free_in_sg;

	req->sgs = sgs;
	req->out_sgs = out_nsgs;
	req->in_sgs = in_nsgs;
	virtaccel_timer_stop("accel > operation > create sg lists", sess);

	virtaccel_timer_start("accel > operation > do req", sess);
	ret = virtaccel_req_submit(req);
	virtaccel_timer_stop("accel > operation > do req", sess);

	return ret;

free_in_sg:
	if (u_op->in_nr)
		sg_cleanup_vaccel_args(&sgs[out_nsgs]);
free_out_sg:
	if (u_op->out_nr)
		sg_cleanup_vaccel_args(&sgs[1]);
free_sgs:
	kfree(sgs);
	req->sgs = NULL;
free_request:
	kfree_sensitive(req->out_arg_hdrs);
	kfree_sensitive(req->in_arg_hdrs);
	h->out_nr = 0;
	h->in_nr = 0;

	complete(&req->completion);
	return ret;
}

static int virtaccel_write_user_output(struct virtio_accel_req *req)
{
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct accel_op_req *op_req = req->priv;
	struct accel_op *u_op = &op_req->u_op;
	int i;
	int ret;

	if (!req)
		return -EINVAL;

	if (!u_op->in_nr)
		return 0;

	for (i = 0; i < u_op->in_nr; i++) {
		op_req->in[i].len =
			virtio32_to_cpu(vdev, req->in_arg_hdrs[i].len);
		op_req->in[i].type =
			virtio32_to_cpu(vdev, req->in_arg_hdrs[i].type);
		op_req->in[i].custom_type_id = virtio32_to_cpu(
			vdev, req->in_arg_hdrs[i].custom_type_id);
	}

	if (unlikely(copy_to_user(u64_to_user_ptr(u_op->in), op_req->in,
				  u_op->in_nr * sizeof(*op_req->in))))
		return -EFAULT;

	for (i = 0; i < u_op->in_nr; i++) {
		ret = accel_buf_copy_to_user(&op_req->in_bufs[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int virtaccel_handle_timers(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op_req *op_req = req->priv;
	struct accel_prof_region *accel_timers;
	struct accel_prof_sample **tmp_samples;
	int ret;
	int *nt;
	int *qnt;
	int i;
	int nr_timers;

	struct virtio_accel_sess *sess =
		virtaccel_session_get_by_id(op_req->u_op.session_id, req);

	nt = (int *)accel_buf_map(&op_req->in_bufs[0]);
	if (!nt)
		return -ENOMEM;

	if (*nt == 0) {
		*nt = sess->nr_timers;
		return 0;
	}

	qnt = (int *)accel_buf_map(&op_req->in_bufs[1]);
	if (!qnt)
		return -ENOMEM;

	nr_timers = (*nt) + (*qnt);
	if (h->in_nr < 3 + nr_timers)
		return -EINVAL;

	accel_timers =
		(struct accel_prof_region *)accel_buf_map(&op_req->in_bufs[2]);
	if (!accel_timers)
		return -ENOMEM;

	if (req->in_arg_hdrs[2].len < nr_timers * sizeof(*accel_timers))
		return -EINVAL;

	tmp_samples =
		kmalloc_array(nr_timers, sizeof(*tmp_samples), GFP_KERNEL);
	if (!tmp_samples)
		return -ENOMEM;

	for (i = 0; i < nr_timers; i++) {
		tmp_samples[i] = accel_timers[i].samples;
		accel_timers[i].samples =
			(struct accel_prof_sample *)accel_buf_map(
				&op_req->in_bufs[3 + i]);
		if (!accel_timers[i].samples)
			goto free_samples;
	}

	ret = virtaccel_timers_virtio_to_accel(accel_timers, nr_timers, sess);

free_samples:
	while (i--)
		accel_timers[i].samples = tmp_samples[i];

	kfree(tmp_samples);
	return ret;
}

void virtaccel_req_handle_result(struct virtio_accel_req *req)
{
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op_req *op_req = req->priv;
	struct accel_op *u_op = &op_req->u_op;
	int ret;

	if (req->status != VIRTIO_ACCEL_OK) {
		u_op->ret = virtio32_to_cpu(vdev, u_op->ret);
		if (h->cmd != VIRTIO_ACCEL_CMD_DESTROY_SESSION) {
			ret = copy_to_user(req->usr, u_op, sizeof(*u_op));
			if (unlikely(ret)) {
				req->ret = -EINVAL;
				return;
			}
		}

		return;
	}

	switch (h->cmd) {
	case VIRTIO_ACCEL_CMD_CREATE_SESSION:
		u_op->session_id = virtio64_to_cpu(vdev, u_op->session_id);
		if (u_op->session_id &&
		    !virtaccel_session_create_and_add(u_op->session_id, req)) {
			req->ret = -ENOMEM;
			break;
		}

		ret = copy_to_user(req->usr, u_op, sizeof(*u_op));
		if (unlikely(ret)) {
			req->ret = -EINVAL;
			break;
		}
		break;
	case VIRTIO_ACCEL_CMD_DESTROY_SESSION:
		virtaccel_session_delete(u_op->session_id, req);
		break;
	case VIRTIO_ACCEL_CMD_DO_OP:
		break;
	case VIRTIO_ACCEL_CMD_GET_TIMERS:
		ret = virtaccel_handle_timers(req);
		if (ret < 0)
			req->ret = ret;
		break;
	default:
		req->ret = -EBADMSG;
		break;
	}
	if (req->ret < 0)
		return;

	ret = virtaccel_write_user_output(req);
	if (ret)
		req->ret = ret;
}

static uint64_t generate_request_id(struct virtio_accel *vaccel)
{
	return atomic64_fetch_inc(&vaccel->next_request_id);
}

static int submit_single_req(struct virtio_accel_req *req)
{
	struct virtio_accel *va = req->vaccel;
	int ret;
	unsigned long flags;

	// Select vq[0] explicitly for now
	spin_lock_irqsave(&va->vq[0].lock, flags);
	ret = virtqueue_add_sgs(va->vq[0].vq, req->sgs, req->out_sgs,
				req->in_sgs, req, GFP_ATOMIC);
	if (unlikely(ret < 0)) {
		spin_unlock_irqrestore(&va->vq[0].lock, flags);
		complete(&req->completion);
		return ret;
	}

	virtqueue_kick(va->vq[0].vq);
	spin_unlock_irqrestore(&va->vq[0].lock, flags);

	return -EINPROGRESS;
}

static unsigned int count_total_sgs(struct virtio_accel_req *req)
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

static unsigned int collect_chunk_sgs(
	struct scatterlist **sgs, unsigned int out_sgs, unsigned int in_sgs,
	unsigned int sg_offset, unsigned int chunk_sg_total_count,
	unsigned int chunk_sg_count, struct scatterlist **chunk_sgs,
	unsigned int *chunk_sg_col_total_count, unsigned int *chunk_out_sgs,
	unsigned int *chunk_in_sgs, struct virtio_accel_sg_allocs *chunk_allocs)
{
	unsigned int curr_sg_idx = 0;
	unsigned int chunk_sg_idx = 0;
	unsigned int collect_sg_total_count = 0;
	unsigned int collect_out_sgs = 0;
	unsigned int collect_in_sgs = 0;
	unsigned int sg_count = out_sgs + in_sgs;
	unsigned int ent_idx;
	struct virtio_accel_sg_allocs *allocs = chunk_allocs ? chunk_allocs :
							       NULL;
	bool count_only = (chunk_sgs == NULL);

	if (!count_only && allocs) {
		allocs->chains = kcalloc(chunk_sg_count,
					 sizeof(*allocs->chains), GFP_KERNEL);
		if (!allocs->chains)
			return 0;
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

		virtaccel_debug(
			"Processing SG entry %u with %u chained entries\n",
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
			virtaccel_debug(
				"  Taking %u SGs from entry %u (starting at offset %u)\n",
				ent_collect_sgs, ent_idx, ent_chunk_offset);

			if (ent_collect_sgs == ent_sg_total_count &&
			    ent_chunk_offset == 0) {
				// Take the entire argument chain as-is
				chunk_sgs[chunk_sg_idx] = ent_sg_chain;
				virtaccel_debug(
					"  Using complete entry chain\n");
			} else {
				// Create a new sub-chain
				struct scatterlist *new_chain =
					create_sg_subchain(ent_sg_chain,
							   ent_chunk_offset,
							   ent_collect_sgs);
				if (!new_chain) {
					virtaccel_err(
						"Failed to create sub-chain\n");
					goto free_allocs;
				}
				chunk_sgs[chunk_sg_idx] = new_chain;
				if (allocs)
					allocs->chains[allocs->count++] =
						new_chain;
				virtaccel_debug(
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
		virtaccel_debug(
			"Collected %u data SGs/SG chains (%u out, %u in), %u total data SGs\n",
			chunk_sg_idx, collect_out_sgs, collect_in_sgs,
			collect_sg_total_count);
	}

	return chunk_sg_idx;

free_allocs:
	for (unsigned int i = 0; i < allocs->count; i++)
		kfree(allocs->chains[i]);

	kfree(allocs->chains);
	return 0;
}

static unsigned int create_chunk_request(struct virtio_accel_req *parent,
					 unsigned int chunk_sg_max_count,
					 unsigned int sg_data_offset,
					 unsigned int sg_total_count,
					 struct virtio_accel_req **chunk_req)
{
	unsigned int chunk_sg_data_total_count = min(
		chunk_sg_max_count - 2, sg_total_count - 1 - sg_data_offset);
	unsigned int sg_count = parent->out_sgs + parent->in_sgs;
	unsigned int chunk_sg_data_count;
	unsigned int chunk_sg_count;
	unsigned int collect_sg_count;
	unsigned int collect_sg_total_count;
	struct scatterlist **chunk_sgs;

	struct virtio_accel_req *chunk = virtaccel_req_new_with_parent(parent);
	if (!chunk)
		return 0;

	// Calculate chunk data SG count
	chunk_sg_data_count = collect_chunk_sgs(
		&parent->sgs[1], parent->out_sgs - 1, parent->in_sgs - 1,
		sg_data_offset, chunk_sg_data_total_count, 0, NULL, NULL, NULL,
		NULL, NULL);
	if (!chunk_sg_data_count)
		return 0;

	chunk_sg_count = chunk_sg_data_count + 2;
	chunk_sgs = kcalloc(chunk_sg_count, sizeof(*chunk_sgs), GFP_KERNEL);
	if (!chunk_sgs)
		goto free_chunk;

	virtaccel_debug("Creating chunk: data_offset=%u, count=%u\n",
			sg_data_offset, chunk_sg_count);

	// Create data SG subset for this chunk
	collect_sg_count = collect_chunk_sgs(
		&parent->sgs[1], parent->out_sgs - 1, parent->in_sgs - 1,
		sg_data_offset, chunk_sg_data_total_count, chunk_sg_data_count,
		&chunk_sgs[1], &collect_sg_total_count, &chunk->out_sgs,
		&chunk->in_sgs, &chunk->chunk_allocs);
	if (collect_sg_count != chunk_sg_data_count)
		goto free_chunk_sgs;

	// First entry is always the header (shared across all chunks)
	chunk_sgs[0] = parent->sgs[0];
	chunk->out_sgs++;

	// Last entry is always the status (shared across all chunks)
	chunk_sgs[collect_sg_count + 1] = parent->sgs[sg_count - 1];
	chunk->in_sgs++;

	chunk->sgs = chunk_sgs;
	*chunk_req = chunk;

	virtaccel_debug("Chunk created with out_sgs=%u, in_sgs=%u\n",
			chunk->out_sgs, chunk->in_sgs);

	return collect_sg_total_count;

free_chunk_sgs:
	kfree(chunk_sgs);
free_chunk:
	kfree(chunk);

	return 0;
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

static int submit_chunked_req(struct virtio_accel_req *parent_req)
{
	struct virtio_accel *vaccel = parent_req->vaccel;
	unsigned int sg_total_count = count_total_sgs(parent_req);
	unsigned int total_chunks =
		calculate_sg_chunks(sg_total_count, MAX_SGS_PER_CHUNK);
	unsigned int sg_data_offset = 0;
	int ret;

	parent_req->hdr.request_id = generate_request_id(vaccel);
	parent_req->hdr.total_chunks = total_chunks;
	atomic_set(&parent_req->chunk_count, total_chunks);

	for (unsigned int i = 0; i < total_chunks; i++) {
		struct virtio_accel_req *chunk_req;

		unsigned int sg_collect_count = create_chunk_request(
			parent_req, MAX_SGS_PER_CHUNK, sg_data_offset,
			sg_total_count, &chunk_req);
		if (!sg_collect_count)
			return -ENOMEM;

		virtaccel_debug("Submitting chunk %u for request id %llu\n", i,
				chunk_req->hdr.request_id);

		ret = submit_single_req(chunk_req);
		if (ret != -EINPROGRESS)
			return ret;

		sg_data_offset += sg_collect_count;
	}

	return -EINPROGRESS;
}

int virtaccel_req_submit(struct virtio_accel_req *req)
{
	unsigned int sg_total_count = count_total_sgs(req);

	if (sg_total_count <= VIRTQUEUE_MAX_SIZE) {
		return submit_single_req(req);
	} else {
		return submit_chunked_req(req);
	}
}
