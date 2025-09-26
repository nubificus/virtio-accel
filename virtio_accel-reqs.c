// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "accel.h"
#include "virtio_accel-common.h"
#include "virtio_accel-prof.h"

static int virtaccel_get_user_buf(struct virtio_accel_arg *v, int write,
				  struct virtio_device *vdev)
{
	int ret = 0;
#ifdef ZC
	struct page **m_pages;
	struct sg_table *m_sgt;

	if (!v || !v->usr_buf || !v->hdr.len || !vdev)
		return -EINVAL;

	ret = virtaccel_map_user_buf(&m_sgt, &m_pages, v->usr_buf,
				     virtio32_to_cpu(vdev, v->hdr.len), write,
				     vdev);
	if (ret > 0) {
		v->buf = m_sgt;
		v->usr_pages = m_pages;
		v->usr_npages = (unsigned int)ret;
	}
#else
	if (!v || !v->hdr.len)
		return -EINVAL;

	v->buf = kzalloc_node(v->hdr.len, GFP_ATOMIC, dev_to_node(&vdev->dev));
	if (!v->buf)
		return -ENOMEM;
#endif

	return ret;
}

static void virtaccel_free_buf(struct virtio_accel_arg *v)
{
	if (!v->buf)
		return;

#ifdef ZC
	virtaccel_unmap_user_buf((struct sg_table *)v->buf, v->usr_pages,
				 v->usr_npages);
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	kzfree(v->buf);
#else
	kfree_sensitive(v->buf);
#endif
#endif
}

static int virtaccel_prepare_args(struct virtio_accel_arg **vargs,
				  struct accel_arg *user_args, u32 nr_args,
				  bool write, struct virtio_device *vdev)
{
	struct accel_arg *args;
	struct virtio_accel_arg *v;
	int ret;
	int i;

	if (!vargs || (nr_args && !user_args) || !vdev)
		return -EINVAL;

	if (!nr_args) {
		*vargs = NULL;
		return 0;
	}

	v = kzalloc_node(nr_args * sizeof(*v), GFP_ATOMIC,
			 dev_to_node(&vdev->dev));
	if (!v)
		return -ENOMEM;

	args = kzalloc_node(nr_args * sizeof(*args), GFP_ATOMIC,
			    dev_to_node(&vdev->dev));
	if (!args) {
		ret = -ENOMEM;
		goto free_vargs;
	}

	if (unlikely(
		    copy_from_user(args, user_args, nr_args * sizeof(*args)))) {
		ret = -EFAULT;
		goto free_args;
	}

	for (i = 0; i < nr_args; i++) {
		v[i].hdr.len = cpu_to_virtio32(vdev, args[i].len);
		v[i].hdr.type = cpu_to_virtio32(vdev, args[i].type);
		v[i].hdr.custom_type_id =
			cpu_to_virtio32(vdev, args[i].custom_type_id);
		v[i].usr_buf = u64_to_user_ptr(args[i].buf);
		ret = virtaccel_get_user_buf(&v[i], write, vdev);
		if (ret < 0)
			goto free_vargs_buf;
	}

	kfree(args);
	*vargs = v;

	return nr_args;

free_vargs_buf:
	for (int j = 0; j < i; j++)
		virtaccel_free_buf(&v[j]);
free_args:
	kfree(args);
	return ret;
free_vargs:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	kzfree(v);
#else
	kfree_sensitive(v);
#endif
	return ret;
}

static int virtaccel_copy_args(struct virtio_accel_arg *vargs, u32 nr_args)
{
#ifndef ZC
	for (int i = 0; i < nr_args; ++i) {
		if (!vargs[i].hdr.len || !vargs[i].buf)
			return -EINVAL;

		if (unlikely(copy_from_user(vargs[i].buf, vargs[i].usr_buf,
					    vargs[i].hdr.len)))
			return -EFAULT;
	}
#endif

	return 0;
}

static void virtaccel_cleanup_args(struct virtio_accel_arg *vargs, u32 nr_args)
{
	if (!vargs)
		return;

	for (int i = 0; i < nr_args; ++i)
		virtaccel_free_buf(&vargs[i]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	kzfree(vargs);
#else
	kfree_sensitive(vargs);
#endif
}

static int virtaccel_prepare_request(struct virtio_device *vdev, u32 cmd,
				     struct virtio_accel_req *req,
				     struct accel_op *op)
{
	struct virtio_accel_hdr *h = &req->hdr;
	int ret;
	int total_sgs = 0;

	virtaccel_debug(
		"Request session_id=%llu, cmd=%u, op_code=%u, out_nr=%u, in_nr=%u\n",
		op->session_id, cmd, op->op_code, op->out_nr, op->in_nr);

	h->session_id = cpu_to_virtio32(vdev, op->session_id);
	h->cmd = cpu_to_virtio32(vdev, cmd);
	h->op_code = cpu_to_virtio32(vdev, op->op_code);

	ret = virtaccel_prepare_args(&req->out_args, op->out, op->out_nr, 0,
				     vdev);
	if (ret < 0)
		return ret;

	total_sgs += 2 * ret;
	h->out_nr = cpu_to_virtio32(vdev, op->out_nr);

	ret = virtaccel_copy_args(req->out_args, op->out_nr);
	if (ret < 0)
		goto free_out;

	ret = virtaccel_prepare_args(&req->in_args, op->in, op->in_nr, 1, vdev);
	if (ret < 0)
		goto free_out;

	total_sgs += 2 * ret;
	h->in_nr = cpu_to_virtio32(vdev, op->in_nr);

	ret = virtaccel_copy_args(req->in_args, op->in_nr);
	if (ret < 0)
		goto free_in;

	return total_sgs;

free_in:
	virtaccel_cleanup_args(req->in_args, op->in_nr);
free_out:
	virtaccel_cleanup_args(req->out_args, op->out_nr);

	return ret;
}

static void sg_cleanup(struct scatterlist *sg)
{
	kfree(sg);
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
			      struct virtio_accel_arg *vargs, u32 nr_args,
			      struct virtio_device *vdev)
{
	struct scatterlist *sg;
	int i, ret, sg_idx = 0;

	if (!sgs || (nr_args && !vargs) || !vdev)
		return -EINVAL;

	if (!nr_args)
		return 0;

	sg = kmalloc_node(2 * nr_args * sizeof(*sg), GFP_ATOMIC,
			  dev_to_node(&vdev->dev));
	if (!sg)
		return -ENOMEM;

	for (i = 0; i < nr_args; i++) {
		ret = sg_add_vaccel_one(&sgs[sg_idx], &sg[sg_idx],
					&vargs[i].hdr, sizeof(vargs[i].hdr));
		if (ret < 0) {
			virtaccel_err("Failed to add argument %d header\n", i);
			return ret;
		}
		sg_idx++;
	}

	for (i = 0; i < nr_args; i++) {
		ret = sg_add_vaccel_one(&sgs[sg_idx], &sg[sg_idx], vargs[i].buf,
					vargs[i].hdr.len);
		if (ret < 0) {
			virtaccel_err(
				"Failed to add argument %d buffer (size: %u)\n",
				i, vargs[i].hdr.len);
			return ret;
		}
		sg_idx++;
	}

	return sg_idx;
}

#else

static int sg_add_vaccel_one_zc(struct scatterlist **sgs, void *ptr, u32 size)
{
	struct sg_table *sgt;

	if (!sgs || !ptr || !size)
		return -EINVAL;

	sgt = (struct sg_table *)ptr;
	*sgs = sgt->sgl;

	return 1;
}

static int sg_add_vaccel_args(struct scatterlist **sgs,
			      struct virtio_accel_arg *vargs, u32 nr_args,
			      struct virtio_device *vdev)
{
	struct scatterlist *sg;
	int i, ret, sg_idx = 0;

	if (!sgs || (nr_args && !vargs) || !vdev)
		return -EINVAL;

	if (!nr_args)
		return 0;

	sg = kmalloc_node(nr_args * sizeof(*sg), GFP_ATOMIC,
			  dev_to_node(&vdev->dev));
	if (!sg)
		return -ENOMEM;

	for (i = 0; i < nr_args; i++) {
		ret = sg_add_vaccel_one(&sgs[sg_idx++], &sg[i], &vargs[i].hdr,
					sizeof(vargs[i].hdr));
		if (ret < 0) {
			virtaccel_err("Failed to add argument %d header\n", i);
			return ret;
		}
	}

	for (i = 0; i < nr_args; i++) {
		ret = sg_add_vaccel_one_zc(&sgs[sg_idx++], vargs[i].buf,
					   vargs[i].hdr.len);
		if (ret < 0) {
			virtaccel_err(
				"Failed to add argument %d buffer (size: %u)\n",
				i, vargs[i].hdr.len);
			return ret;
		}
	}

	return sg_idx;
}
#endif

struct virtio_accel_req *virtaccel_req_new(struct virtio_accel *vaccel,
					   void __user *usr)
{
	struct virtio_accel_req *req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->vaccel = vaccel;
	req->out_args = NULL;
	req->in_args = NULL;
	req->sgs = NULL;

	req->parent = NULL;
	atomic_set(&req->chunk_count, 0);
	req->chunk_allocs.chains = NULL;

	req->priv = NULL;
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
	req->out_args = NULL;
	req->in_args = NULL;
	req->sgs = NULL;

	req->parent = parent;
	atomic_set(&req->chunk_count, 0);
	req->chunk_allocs.chains = NULL;

	req->priv = parent->priv;
	req->usr = parent->usr;

	init_completion(&req->completion);
	return req;
}

static void clear_parent(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h;

	if (!req)
		return;

	h = &req->hdr;
	if (h->out_nr)
		sg_cleanup(req->sgs[1]);
	if (h->in_nr)
		sg_cleanup(req->sgs[req->out_sgs]);

	virtaccel_cleanup_args(req->out_args, h->out_nr);
	virtaccel_cleanup_args(req->in_args, h->in_nr);
}

static void clear_chunk(struct virtio_accel_req *req)
{
	if (!req)
		return;

	for (unsigned int i = 0; i < req->chunk_allocs.count; i++) {
		kfree(req->chunk_allocs.chains[i]);
	}
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

	memset(&req->hdr, 0, sizeof(req->hdr));
	req->out_args = NULL;
	req->in_args = NULL;

	kfree(req->sgs);
	req->sgs = NULL;
	req->out_sgs = 0;
	req->in_sgs = 0;

	req->parent = NULL;
	atomic_set(&req->chunk_count, 0);
	req->chunk_allocs.chains = NULL;
	req->chunk_allocs.count = 0;

	req->priv = NULL;
	req->usr = NULL;
	req->ret = 0;
}

void virtaccel_req_delete(struct virtio_accel_req *req)
{
	if (!req)
		return;

	if (!req->parent && !completion_done(&req->completion))
		return;

	virtaccel_req_clear(req);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	kzfree(req);
#else
	kfree_sensitive(req);
#endif
}

int virtaccel_req_operation(struct virtio_accel_req *req, u32 cmd)
{
	struct scatterlist hdr_sg;
	struct scatterlist status_sg;
	struct scatterlist sid_sg;
	struct scatterlist ret_sg;
	struct scatterlist **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op *op = req->priv;
	int ret;
	int out_nsgs = 0;
	int in_nsgs = 0;

	// Start with required SGs [hdr + ret + status (+ sid)]
	int total_sgs = (cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) ? 4 : 3;

	struct virtio_accel_sess *sess =
		(cmd != VIRTIO_ACCEL_CMD_GET_TIMERS) ?
			virtaccel_session_get_by_id(op->session_id, req) :
			NULL;

	virtaccel_timer_start("accel > operation > prepare request", sess);
	ret = virtaccel_prepare_request(vdev, cmd, req, op);
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

	/* virtio header */
	ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdr_sg, h, sizeof(*h));
	if (ret < 0)
		goto free_sgs;

	/* user out arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], req->out_args, h->out_nr,
				 vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user read arguments: %d\n", ret);
		goto free_sgs;
	}

	out_nsgs += ret;

	/* user in arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs + in_nsgs], req->in_args,
				 h->in_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user write arguments: %d\n", ret);
		goto free_out_sg;
	}

	in_nsgs += ret;

	if (cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) {
		/* session id */
		ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &sid_sg,
					&op->session_id,
					sizeof(op->session_id));
		if (ret < 0)
			goto free_in_sg;
	}

	/* operation return value */
	ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &ret_sg, &op->ret,
				sizeof(op->ret));
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
	if (op->in_nr)
		sg_cleanup(sgs[out_nsgs]);
free_out_sg:
	if (op->out_nr)
		sg_cleanup(sgs[1]);
free_sgs:
	kfree(sgs);
	req->sgs = NULL;
free_request:
	virtaccel_cleanup_args(req->out_args, op->out_nr);
	virtaccel_cleanup_args(req->in_args, op->in_nr);
	h->out_nr = 0;
	h->in_nr = 0;

	complete(&req->completion);
	return ret;
}

static int virtaccel_write_user_output(struct virtio_accel_arg *varg,
				       u32 nr_arg)
{
#ifndef ZC
	if (!nr_arg)
		return 0;

	for (int i = 0; i < nr_arg; ++i) {
		if (unlikely(copy_to_user(varg[i].usr_buf, varg[i].buf,
					  varg[i].hdr.len)))
			return -EINVAL;
	}
#endif

	return 0;
}

static void *virtaccel_get_prepared_buf(struct virtio_accel_arg *varg,
					struct virtio_device *vdev)
{
#ifdef ZC
	void *b = vmap(varg->usr_pages, varg->usr_npages, VM_MAP, PAGE_KERNEL);
	if (b)
		return b + PAGEOFFSET((unsigned long)varg->usr_buf);

	return b;
#else
	return varg->buf;
#endif
}

static void virtaccel_put_prepared_buf(struct virtio_accel_arg *varg, void *buf)
{
#ifdef ZC
	vunmap(buf - PAGEOFFSET((unsigned long)varg->usr_buf));
#endif
}

static int virtaccel_handle_timers(struct virtio_accel_req *req)
{
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op *op = req->priv;
	struct accel_prof_region *accel_timers;
	struct accel_prof_sample **tmp_samples;
	int ret = 0;
	int *nt;
	int *qnt;
	int i;
	int nr_timers;

	struct virtio_accel_sess *sess =
		virtaccel_session_get_by_id(op->session_id, req);

	nt = (int *)virtaccel_get_prepared_buf(&req->in_args[0], vdev);
	if (!nt) {
		ret = -ENOMEM;
		goto out;
	}

	if (*nt == 0) {
		*nt = sess->nr_timers;
	} else {
		qnt = (int *)virtaccel_get_prepared_buf(&req->in_args[1], vdev);
		if (!qnt) {
			ret = -ENOMEM;
			goto out_nt;
		}

		nr_timers = (*nt) + (*qnt);
		if (h->in_nr < 3 + nr_timers) {
			ret = -EINVAL;
			goto out_qnt;
		}

		accel_timers =
			(struct accel_prof_region *)virtaccel_get_prepared_buf(
				&req->in_args[2], vdev);
		if (req->in_args[2].hdr.len <
		    nr_timers * sizeof(*accel_timers)) {
			ret = -EINVAL;
			goto out_qnt;
		}
		tmp_samples =
			kzalloc(nr_timers * sizeof(*tmp_samples), GFP_KERNEL);
		if (!tmp_samples) {
			ret = -ENOMEM;
			goto out_at;
		}

		for (i = 0; i < nr_timers; i++) {
			tmp_samples[i] = accel_timers[i].samples;
			accel_timers[i].samples = (struct accel_prof_sample *)
				virtaccel_get_prepared_buf(&req->in_args[3 + i],
							   vdev);
		}

		ret = virtaccel_timers_virtio_to_accel(accel_timers, nr_timers,
						       sess);
		if (ret < 0)
			goto out_tmp_samples;

		for (i = 0; i < nr_timers; i++) {
			virtaccel_put_prepared_buf(
				&req->in_args[3 + i],
				(void *)accel_timers[i].samples);
			accel_timers[i].samples = tmp_samples[i];
		}

out_tmp_samples:
		kfree(tmp_samples);
out_at:
		virtaccel_put_prepared_buf(&req->in_args[2],
					   (void *)accel_timers);
out_qnt:
		virtaccel_put_prepared_buf(&req->in_args[1], (void *)qnt);
	}

out_nt:
	virtaccel_put_prepared_buf(&req->in_args[0], (void *)nt);
out:
	return ret;
}

void virtaccel_req_handle_result(struct virtio_accel_req *req)
{
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op *op = req->priv;
	int ret;

	if (req->status != VIRTIO_ACCEL_OK) {
		op->ret = virtio32_to_cpu(vdev, op->ret);
		if (h->cmd != VIRTIO_ACCEL_CMD_DESTROY_SESSION) {
			ret = copy_to_user(req->usr, op, sizeof(*op));
			if (unlikely(ret)) {
				req->ret = -EINVAL;
				return;
			}
		}

		return;
	}

	switch (h->cmd) {
	case VIRTIO_ACCEL_CMD_CREATE_SESSION:
		op->session_id = virtio64_to_cpu(vdev, op->session_id);
		if (!virtaccel_session_create_and_add(op->session_id, req)) {
			req->ret = -ENOMEM;
			break;
		}

		ret = copy_to_user(req->usr, op, sizeof(*op));
		if (unlikely(ret)) {
			req->ret = -EINVAL;
			break;
		}
		break;
	case VIRTIO_ACCEL_CMD_DESTROY_SESSION:
		virtaccel_session_delete(op->session_id, req);
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

	ret = virtaccel_write_user_output(req->in_args, h->in_nr);
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
	unsigned int *chunk_in_sgs, struct chunk_sg_allocs *chunk_allocs)
{
	unsigned int curr_sg_idx = 0;
	unsigned int chunk_sg_idx = 0;
	unsigned int collect_sg_total_count = 0;
	unsigned int collect_out_sgs = 0;
	unsigned int collect_in_sgs = 0;
	unsigned int sg_count = out_sgs + in_sgs;
	unsigned int ent_idx;
	struct chunk_sg_allocs *allocs = chunk_allocs ? chunk_allocs : NULL;
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
