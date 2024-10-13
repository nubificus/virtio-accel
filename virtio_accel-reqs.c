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

	if (!v || !v->usr_buf || !v->len)
		return -EINVAL;

	ret = virtaccel_map_user_buf(&m_sgt, &m_pages, v->usr_buf, v->len,
				     write, vdev);
	if (ret > 0) {
		v->buf = (__u8 *)m_sgt;
		v->usr_pages = (__u8 *)m_pages;
		v->usr_npages = cpu_to_virtio32(vdev, ret);
	}
#else
	if (!v || !v->len)
		return -EINVAL;

	v->buf = kzalloc_node(v->len, GFP_ATOMIC, dev_to_node(&vdev->dev));
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
	virtaccel_unmap_user_buf((struct sg_table *)v->buf,
				 (struct page **)v->usr_pages, v->usr_npages);
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
				  struct virtio_device *vdev)
{
	struct accel_arg *args;
	struct virtio_accel_arg *v;
	int ret;

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

	if (!user_args) {
		ret = -EINVAL;
		goto free_args;
	}

	if (unlikely(
		    copy_from_user(args, user_args, nr_args * sizeof(*args)))) {
		ret = -EFAULT;
		goto free_args;
	}

	for (int i = 0; i < nr_args; ++i) {
		v[i].len = cpu_to_virtio32(vdev, args[i].len);
		v[i].usr_buf = args[i].buf;
		ret = virtaccel_get_user_buf(&v[i], 1, vdev);
		if (ret < 0)
			goto free_vargs_buf;
	}

	kfree(args);
	*vargs = v;

	return nr_args + 1;

free_vargs_buf:
	for (int i = 0; i < nr_args; ++i)
		virtaccel_free_buf(&v[i]);
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
	int i;

	for (i = 0; i < nr_args; ++i) {
		if (!vargs[i].len || !vargs[i].buf)
			return -EINVAL;

		if (unlikely(copy_from_user(vargs[i].buf, vargs[i].usr_buf,
					    vargs[i].len)))
			return -EFAULT;
	}
#endif

	return 0;
}

static void virtaccel_cleanup_args(struct virtio_accel_arg *vargs, u32 nr_args)
{
	int i;

	if (!vargs)
		return;

	for (i = 0; i < nr_args; ++i)
		virtaccel_free_buf(&vargs[i]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	kzfree(vargs);
#else
	kfree_sensitive(vargs);
#endif
}

static int virtaccel_prepare_request(struct virtio_device *vdev, u32 op_type,
				     struct virtio_accel_hdr *virtio,
				     struct accel_session *usr_sess)
{
	struct accel_op *op = &usr_sess->op;
	int ret;
	int total_sgs = 0;

	virtio->sess_id = cpu_to_virtio32(vdev, usr_sess->id);
	virtio->op_type = cpu_to_virtio32(vdev, op_type);
	virtio->op.out_nr = cpu_to_virtio32(vdev, op->out_nr);
	virtio->op.in_nr = cpu_to_virtio32(vdev, op->in_nr);

	virtaccel_debug("Request id: %d, type: %d, out_nr: %d, in_nr: %d\n",
			virtio->sess_id, virtio->op_type, virtio->op.out_nr,
			virtio->op.in_nr);

	ret = virtaccel_prepare_args(&virtio->op.out, usr_sess->op.out,
				     virtio->op.out_nr, vdev);
	if (ret < 0)
		return ret;

	total_sgs += ret;

	ret = virtaccel_copy_args(virtio->op.out, virtio->op.out_nr);
	if (ret < 0)
		goto free_out;

	ret = virtaccel_prepare_args(&virtio->op.in, usr_sess->op.in,
				     virtio->op.in_nr, vdev);
	if (ret < 0)
		goto free_out;

	total_sgs += ret;

	ret = virtaccel_copy_args(virtio->op.in, virtio->op.in_nr);
	if (ret < 0)
		goto free_in;

	return total_sgs;

free_in:
	virtaccel_cleanup_args(virtio->op.in, virtio->op.in_nr);
free_out:
	virtaccel_cleanup_args(virtio->op.out, virtio->op.out_nr);

	return ret;
}

static void sg_cleanup(struct scatterlist *sg)
{
#ifndef ZC
	kfree(sg);
#endif
}

static int sg_add_vaccel_one(struct scatterlist **sgs, struct scatterlist *sg,
			     void *ptr, u32 size)
{
	if (!ptr || !size)
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
	int i, ret;

	if (!nr_args)
		return 0;

	sg = kmalloc_node(nr_args * sizeof(*sg), GFP_ATOMIC,
			  dev_to_node(&vdev->dev));
	if (!sg)
		return -ENOMEM;

	for (i = 0; i < nr_args; i++) {
		ret = sg_add_vaccel_one(&sgs[i], &sg[i], vargs[i].buf,
					vargs[i].len);
		if (ret < 0) {
			virtaccel_err("Failed to add argument %d (size: %u)\n",
				      i, vargs[i].len);
			return ret;
		}
	}

	return i;
}
#else

static int sg_add_vaccel_one_zc(struct scatterlist **sgs, void *ptr, u32 size)
{
	struct sg_table *sgt;

	if (!ptr || !size)
		return -EINVAL;

	sgt = (struct sg_table *)ptr;
	*sgs = sgt->sgl;

	return 1;
}

static int sg_add_vaccel_args(struct scatterlist **sgs,
			      struct virtio_accel_arg *vargs, u32 nr_args,
			      struct virtio_device *vdev)
{
	int i, ret;

	if (!nr_args)
		return 0;

	for (i = 0; i < nr_args; i++) {
		ret = sg_add_vaccel_one_zc(&sgs[i], vargs[i].buf, vargs[i].len);
		if (ret < 0) {
			virtaccel_err("Failed to add argument %d (size: %u)\n",
				      i, vargs[i].len);
			return ret;
		}
	}

	return i;
}
#endif

int virtaccel_req_create_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg;
	struct scatterlist hdrout_sg;
	struct scatterlist hdrin_sg;
	struct scatterlist sid_sg;
	struct scatterlist status_sg;
	struct scatterlist **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;
	int out_nsgs = 0;
	int in_nsgs = 0;
	int total_sgs = 3; // dyn sgs added later

	//virtaccel_timer_start("accel > create session > prepare request", vaccel);
	ret = virtaccel_prepare_request(vdev, VIRTIO_ACCEL_CREATE_SESSION, h,
					sess);
	if (ret < 0) {
		virtaccel_err("Failed to parse user arguments: %d\n", ret);
		return ret;
	}
	//virtaccel_timer_stop("accel > create session > prepare request", vaccel);

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

	/* virtio out arguments header */
	if (h->op.out_nr) {
		ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdrout_sg, h->op.out,
					h->op.out_nr * sizeof(*h->op.out));
		if (ret < 0)
			goto free_sgs;
	}

	/* virtio in arguments header */
	if (h->op.in_nr) {
		ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdrin_sg, h->op.in,
					h->op.in_nr * sizeof(*h->op.in));
		if (ret < 0)
			goto free_sgs;
	}

	/* user out arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.out, h->op.out_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user read arguments: %d\n", ret);
		goto free_sgs;
	}

	out_nsgs += ret;

	/* user in arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.in, h->op.in_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user write arguments: %d\n", ret);
		goto free_out_sg;
	}

	in_nsgs += ret;

	/* session id */
	ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &sid_sg, &sess->id,
				sizeof(sess->id));
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
	//virtaccel_timer_stop("accel > create session > create sg lists", vaccel);

	//virtaccel_timer_start("accel > create session > do req", vaccel);
	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		goto free_in_sg;
	//virtaccel_timer_stop("accel > create session > do req", vaccel);

	return ret;

free_in_sg:
	if (sess->op.in_nr)
		sg_cleanup(sgs[out_nsgs]);
free_out_sg:
	if (sess->op.out_nr) {
		if (sess->op.in_nr)
			sg_cleanup(sgs[3]);
		else
			sg_cleanup(sgs[2]);
	}
free_sgs:
	kfree(sgs);
free_request:
	virtaccel_cleanup_args(h->op.out, h->op.out_nr);
	virtaccel_cleanup_args(h->op.in, h->op.in_nr);

	return ret;
}

int virtaccel_req_destroy_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg;
	struct scatterlist status_sg;
	struct scatterlist *sgs[2];
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;

	h->sess_id = cpu_to_virtio32(vdev, sess->id);
	h->op_type = cpu_to_virtio32(vdev, VIRTIO_ACCEL_DESTROY_SESSION);

	sg_add_vaccel_one(&sgs[0], &hdr_sg, h, sizeof(*h));
	sg_add_vaccel_one(&sgs[1], &status_sg, &req->status,
			  sizeof(req->status));

	req->sgs = sgs;
	req->out_sgs = 1;
	req->in_sgs = 1;

	return virtaccel_do_req(req);
}

int virtaccel_req_operation(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg;
	struct scatterlist hdrout_sg;
	struct scatterlist hdrin_sg;
	struct scatterlist status_sg;
	struct scatterlist **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;
	int out_nsgs = 0;
	int in_nsgs = 0;
	int total_sgs = 2; // dyn sgs added later

	struct virtio_accel_sess *vsess =
		virtaccel_session_get_by_id(sess->id, req);

	virtaccel_timer_start("accel > operation > prepare request", vsess);
	ret = virtaccel_prepare_request(vdev, VIRTIO_ACCEL_DO_OP, h, sess);
	if (ret < 0) {
		virtaccel_err("Failed to parse user arguments: %d\n", ret);
		return ret;
	}
	virtaccel_timer_stop("accel > operation > prepare request", vsess);

	virtaccel_timer_start("accel > operation > create sg lists", vsess);
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

	/* virtio header */
	/* virtio out arguments header */
	if (h->op.out_nr) {
		ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdrout_sg, h->op.out,
					h->op.out_nr * sizeof(*h->op.out));
		if (ret < 0)
			goto free_sgs;
	}

	/* virtio in arguments header */
	if (h->op.in_nr) {
		ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdrin_sg, h->op.in,
					h->op.in_nr * sizeof(*h->op.in));
		if (ret < 0)
			goto free_sgs;
	}

	/* user out arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.out, h->op.out_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user read arguments: %d\n", ret);
		goto free_sgs;
	}

	out_nsgs += ret;

	/* user in arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.in, h->op.in_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user write arguments: %d\n", ret);
		goto free_out_sg;
	}

	in_nsgs += ret;

	/* result status */
	ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &status_sg,
				&req->status, sizeof(req->status));
	if (ret < 0)
		goto free_in_sg;

	req->sgs = sgs;
	req->out_sgs = out_nsgs;
	req->in_sgs = in_nsgs;
	virtaccel_timer_stop("accel > operation > create sg lists", vsess);

	virtaccel_timer_start("accel > operation > do req", vsess);
	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		goto free_in_sg;
	virtaccel_timer_stop("accel > operation > do req", vsess);

	return ret;

free_in_sg:
	if (sess->op.in_nr)
		sg_cleanup(sgs[out_nsgs]);
free_out_sg:
	if (sess->op.out_nr) {
		if (sess->op.in_nr)
			sg_cleanup(sgs[3]);
		else
			sg_cleanup(sgs[2]);
	}
free_sgs:
	kfree(sgs);
free_request:
	virtaccel_cleanup_args(h->op.out, h->op.out_nr);
	virtaccel_cleanup_args(h->op.in, h->op.in_nr);

	return ret;
}

static int virtaccel_write_user_output(struct virtio_accel_arg *varg,
				       u32 nr_arg)
{
#ifndef ZC
	int i = 0;

	if (!nr_arg)
		return 0;

	for (i = 0; i < nr_arg; ++i) {
		if (unlikely(copy_to_user(varg[i].usr_buf, varg[i].buf,
					  varg[i].len)))
			return -EINVAL;
	}
#endif

	return 0;
}

static void *virtaccel_get_prepared_buf(struct virtio_accel_arg *varg,
					struct virtio_device *vdev)
{
#ifdef ZC
	void *b = vmap((struct page **)varg->usr_pages,
		       virtio32_to_cpu(vdev, varg->usr_npages), VM_MAP,
		       PAGE_KERNEL);
	if (b)
		return b + PAGEOFFSET((unsigned long)varg->usr_buf);
	else
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

int virtaccel_req_timers(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg;
	struct scatterlist hdrout_sg;
	struct scatterlist hdrin_sg;
	struct scatterlist status_sg;
	struct scatterlist **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;
	int out_nsgs = 0;
	int in_nsgs = 0;
	int total_sgs = 2; // dyn sgs added later

	ret = virtaccel_prepare_request(vdev, VIRTIO_ACCEL_GET_TIMERS, h, sess);
	if (ret < 0)
		return ret;
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

	/* virtio out arguments header */
	if (h->op.out_nr) {
		ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdrout_sg, h->op.out,
					h->op.out_nr * sizeof(*h->op.out));
		if (ret < 0)
			goto free_sgs;
	}

	/* virtio in arguments header */
	if (h->op.in_nr) {
		ret = sg_add_vaccel_one(&sgs[out_nsgs++], &hdrin_sg, h->op.in,
					h->op.in_nr * sizeof(*h->op.in));
		if (ret < 0)
			goto free_sgs;
	}

	/* user out arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.out, h->op.out_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user read arguments: %d\n", ret);
		goto free_sgs;
	}

	out_nsgs += ret;

	/* user in arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.in, h->op.in_nr, vdev);
	if (ret < 0) {
		virtaccel_err("Failed to add user write arguments: %d\n", ret);
		goto free_out_sg;
	}

	in_nsgs += ret;

	/* result status */
	ret = sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &status_sg,
				&req->status, sizeof(req->status));
	if (ret < 0)
		goto free_in_sg;

	req->sgs = sgs;
	req->out_sgs = out_nsgs;
	req->in_sgs = in_nsgs;

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		goto free_in_sg;

	return ret;

free_in_sg:
	if (sess->op.in_nr)
		sg_cleanup(sgs[out_nsgs]);
free_out_sg:
	if (sess->op.out_nr) {
		if (sess->op.in_nr)
			sg_cleanup(sgs[3]);
		else
			sg_cleanup(sgs[2]);
	}
free_sgs:
	kfree(sgs);
free_request:
	virtaccel_cleanup_args(h->op.out, h->op.out_nr);
	virtaccel_cleanup_args(h->op.in, h->op.in_nr);

	return ret;
}

static int virtaccel_handle_timers(struct virtio_accel_req *req)
{
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	struct accel_prof_region *accel_timers;
	struct accel_prof_sample **tmp_samples;
	int ret = 0;
	int *nt;
	int *qnt;
	int i;
	int nr_timers;

	struct virtio_accel_sess *vsess =
		virtaccel_session_get_by_id(sess->id, req);

	nt = (int *)virtaccel_get_prepared_buf(&h->op.in[0], vdev);
	if (!nt) {
		ret = -ENOMEM;
		goto out;
	}

	if (*nt == 0) {
		*nt = vsess->nr_timers;
	} else {
		qnt = (int *)virtaccel_get_prepared_buf(&h->op.in[1], vdev);
		if (!qnt) {
			ret = -ENOMEM;
			goto out_at;
		}

		nr_timers = (*nt) + (*qnt);
		if (h->op.in_nr < 3 + nr_timers) {
			ret = -EINVAL;
			goto out_qnt;
		}

		accel_timers =
			(struct accel_prof_region *)virtaccel_get_prepared_buf(
				&h->op.in[2], vdev);
		if (h->op.in[2].len < nr_timers * sizeof(*accel_timers)) {
			ret = -EINVAL;
			goto out_qnt;
		}
		tmp_samples =
			kzalloc(nr_timers * sizeof(*tmp_samples), GFP_KERNEL);
		if (!tmp_samples) {
			ret = -ENOMEM;
			goto out_qnt;
		}

		for (i = 0; i < nr_timers; i++) {
			tmp_samples[i] = accel_timers[i].samples;
			accel_timers[i].samples = (struct accel_prof_sample *)
				virtaccel_get_prepared_buf(&h->op.in[3 + i],
							   vdev);
		}

		ret = virtaccel_timers_virtio_to_accel(accel_timers, nr_timers,
						       vsess);
		if (ret < 0)
			goto out_qnt;

		for (i = 0; i < nr_timers; i++) {
			virtaccel_put_prepared_buf(
				&h->op.in[3 + i],
				(void *)accel_timers[i].samples);
			accel_timers[i].samples = tmp_samples[i];
		}

out_qnt:
		virtaccel_put_prepared_buf(&h->op.in[1], (void *)qnt);
out_at:
		virtaccel_put_prepared_buf(&h->op.in[2], (void *)accel_timers);
		kfree(tmp_samples);
	}
	virtaccel_put_prepared_buf(&h->op.in[0], (void *)nt);

out:
	return ret;
}

void virtaccel_clear_req(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h = &req->hdr;

	switch (h->op_type) {
	case VIRTIO_ACCEL_DO_OP:
	case VIRTIO_ACCEL_CREATE_SESSION:
	case VIRTIO_ACCEL_GET_TIMERS:
		if (h->op.out_nr) {
			if (h->op.in_nr)
				sg_cleanup(req->sgs[3]);
			else
				sg_cleanup(req->sgs[2]);
		}
		if (h->op.in_nr)
			sg_cleanup(req->sgs[req->out_sgs]);

		kfree(req->sgs);
		virtaccel_cleanup_args(h->op.out, h->op.out_nr);
		virtaccel_cleanup_args(h->op.in, h->op.in_nr);
		fallthrough;
	case VIRTIO_ACCEL_DESTROY_SESSION:
		kfree((struct accel_session *)req->priv);
		break;
	}

	req->sgs = NULL;
	req->usr = NULL;
	req->out_sgs = 0;
	req->in_sgs = 0;
}

void virtaccel_handle_req_result(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;

	if (req->status != VIRTIO_ACCEL_OK)
		return;

	switch (h->op_type) {
	case VIRTIO_ACCEL_CREATE_SESSION:
		ret = virtaccel_write_user_output(h->op.in, h->op.in_nr);
		if (ret) {
			req->ret = -EINVAL;
			return;
		}

		if (!virtaccel_session_create_and_add(sess, req)) {
			req->ret = -ENOMEM;
			return;
		}
		ret = copy_to_user(req->usr, sess, sizeof(*sess));
		if (unlikely(ret)) {
			req->ret = -EINVAL;
			return;
		}
		break;
	case VIRTIO_ACCEL_DESTROY_SESSION:
		virtaccel_session_delete(sess, req);
		break;
	case VIRTIO_ACCEL_DO_OP:
		ret = virtaccel_write_user_output(h->op.in, h->op.in_nr);
		if (ret) {
			req->ret = -EINVAL;
			return;
		}
		break;
	case VIRTIO_ACCEL_GET_TIMERS:
		ret = virtaccel_handle_timers(req);
		if (ret < 0) {
			req->ret = ret;
			return;
		}

		ret = virtaccel_write_user_output(h->op.in, h->op.in_nr);
		if (ret) {
			req->ret = -EINVAL;
			return;
		}
		break;
	default:
		req->ret = -EBADMSG;
		break;
	}
}

int virtaccel_do_req(struct virtio_accel_req *req)
{
	struct virtio_accel *va = req->vaccel;
	int ret;
	unsigned long flags;

	init_completion(&req->completion);

	// select vq[0] explicitly for now
	spin_lock_irqsave(&va->vq[0].lock, flags);
	ret = virtqueue_add_sgs(va->vq[0].vq, req->sgs, req->out_sgs,
				req->in_sgs, req, GFP_ATOMIC);
	virtqueue_kick(va->vq[0].vq);
	spin_unlock_irqrestore(&va->vq[0].lock, flags);
	if (unlikely(ret < 0)) {
		virtaccel_clear_req(req);
		return ret;
	}

	return -EINPROGRESS;
}
