#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "accel.h"
#include "virtio_accel-common.h"

int prepare_virtio_args(struct virtio_accel_arg **vargs,
		struct accel_arg *user_arg, u32 nr_args,
		struct virtio_device *vdev)
{
	struct accel_arg *args;
	struct virtio_accel_arg *v;
	int i, ret;

	if (!nr_args) {
		*vargs = NULL;
		return 0;
	}

	v = kzalloc_node(nr_args * sizeof(*v), GFP_ATOMIC,
			dev_to_node(&vdev->dev));
	if (!v)
		return -ENOMEM;

	args = kmalloc_node(nr_args * sizeof(*args), GFP_ATOMIC,
			dev_to_node(&vdev->dev));
	if (!args) {
		ret = -ENOMEM;
		goto free_vargs;
	}

	if (unlikely(copy_from_user(args, user_arg, nr_args * sizeof(*args)))) {
		ret = -EFAULT;
		goto free_args;
	}

	for (i = 0; i < nr_args; ++i) {
		v[i].len = cpu_to_virtio32(vdev, args[i].len);
		v[i].usr_buf = args[i].buf;
		v[i].buf = kzalloc_node(args[i].len, GFP_ATOMIC,
					dev_to_node(&vdev->dev));
		if (!v[i].buf) {
			ret = -ENOMEM;
			goto free_vargs_buf;
		}
	}

	kfree(args);
	*vargs = v;

	return 0;

free_vargs_buf:
	for (i = 0; i < nr_args; ++i) {
		if (v[i].buf)
			kzfree(v[i].buf);
	}

free_args:
	kfree(args);
	return ret;

free_vargs:
	kzfree(v);
	return ret;
}

int copy_virtio_args(struct virtio_accel_arg *vargs, u32 nr_args)
{
	int i;

	for (i = 0; i < nr_args; ++i) {
		if (unlikely(copy_from_user(vargs[i].buf, vargs[i].usr_buf,
						vargs[i].len)))
			return -EFAULT;
	}

	return 0;
}

void cleanup_virtio_args(struct virtio_accel_arg *vargs, u32 nr_args)
{
	int i;

	if (!vargs)
		return;

	for (i = 0; i < nr_args; ++i)
		if (vargs[i].buf)
			kzfree(vargs[i].buf);

	kzfree(vargs);
}

int prepare_virtio_request(struct virtio_device *vdev, u32 op_type,
		struct virtio_accel_hdr *virtio, struct accel_session *usr_sess)
{
	struct accel_op *op = &usr_sess->op;
	int ret;

	virtio->id = cpu_to_virtio32(vdev, usr_sess->id);
	virtio->op_type = cpu_to_virtio32(vdev, op_type);
	virtio->op.in_nr = cpu_to_virtio32(vdev, op->in_nr);
	virtio->op.out_nr = cpu_to_virtio32(vdev, op->out_nr);

	ret = prepare_virtio_args(&virtio->op.in, usr_sess->op.in,
			virtio->op.in_nr, vdev);
	if (ret)
		return ret;

	ret = prepare_virtio_args(&virtio->op.out, usr_sess->op.out,
			virtio->op.out_nr, vdev);
	if (ret)
		goto free_in;

	ret = copy_virtio_args(virtio->op.out, virtio->op.out_nr);
	if (ret)
		goto free_out;

	return 0;

free_out:
	cleanup_virtio_args(virtio->op.out, virtio->op.out_nr);
free_in:
	cleanup_virtio_args(virtio->op.in, virtio->op.in_nr);

	return ret;
}

void sg_add_vaccel_one(struct scatterlist **sgs, struct scatterlist *sg,
	       	void *ptr, u32 size)
{
	sg_init_one(sg, ptr, size);
	*sgs = sg;
}

int sg_add_vaccel_args(struct scatterlist **sgs, struct virtio_accel_arg *vargs,
		u32 nr_args, struct virtio_device *vdev)
{
	int i;
	struct scatterlist *sg;

	if (!nr_args)
		return 0;

	sg = kmalloc_node(nr_args * sizeof(*sg), GFP_ATOMIC,
			dev_to_node(&vdev->dev));
	if (!sg)
		return -ENOMEM;

	for (i = 0; i < nr_args; ++i)
		sg_add_vaccel_one(&sgs[i], &sg[i], vargs[i].buf, vargs[i].len);

	return 0;
}

int virtaccel_req_create_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, sid_sg, status_sg, *sgs[3];
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;

	h->op_type = cpu_to_virtio32(vdev, VIRTIO_ACCEL_CREATE_SESSION);

	/* virtio header */
	sg_add_vaccel_one(&sgs[0], &hdr_sg, h, sizeof(*h));

	/* session id */
	sg_add_vaccel_one(&sgs[1], &sid_sg, &sess->id,
			sizeof(sess->id));

	/* result status */
	sg_add_vaccel_one(&sgs[2], &status_sg, &req->status,
			sizeof(req->status));

	req->sgs = sgs;
	req->out_sgs = 1;
	req->in_sgs = 2;

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		return ret;

	req->sgs = NULL;
	return ret;
}

int virtaccel_req_destroy_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, status_sg, *sgs[2];
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;

	h->id = cpu_to_virtio32(vdev, sess->id);
	h->op_type = cpu_to_virtio32(vdev, VIRTIO_ACCEL_DESTROY_SESSION);

	sg_add_vaccel_one(&sgs[0], &hdr_sg, h, sizeof(*h));
	sg_add_vaccel_one(&sgs[1], &status_sg, &req->status, sizeof(req->status));

	req->sgs = sgs;
	req->out_sgs = 1;
	req->in_sgs = 1;

	return virtaccel_do_req(req);
}

int virtaccel_req_operation(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, status_sg, **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret, out_nsgs = 0, in_nsgs = 0,
	    total_sgs = 2 + sess->op.in_nr + sess->op.out_nr;

	ret = prepare_virtio_request(vdev, VIRTIO_ACCEL_DO_OP, h, sess);
	if (ret)
		return ret;

	sgs = kmalloc_node(total_sgs * sizeof(*sgs), GFP_ATOMIC,
			dev_to_node(&vdev->dev));
	if (!sgs) {
		ret = -ENOMEM;
		goto free_request;
	}

	/* virtio header */
	sg_add_vaccel_one(&sgs[out_nsgs++], &hdr_sg, h, sizeof(*h));

	/* user out arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.out, h->op.out_nr, vdev);
	if (ret)
		goto free_sgs;

	out_nsgs += h->op.out_nr;

	/* user in arguments */
	ret = sg_add_vaccel_args(&sgs[out_nsgs], h->op.in, h->op.in_nr, vdev);
	if (ret)
		goto free_out_sg;

	in_nsgs += h->op.in_nr;

	/* result status */
	sg_add_vaccel_one(&sgs[out_nsgs + in_nsgs++], &status_sg, &req->status,
			sizeof(req->status));

	req->sgs = sgs;
	req->out_sgs = out_nsgs;
	req->in_sgs = in_nsgs;

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		goto free_in_sg;

	return ret;

free_in_sg:
	if (sess->op.in_nr)
		kfree(sgs[out_nsgs]);
free_out_sg:
	if (sess->op.out_nr)
		kfree(sgs[1]);
free_sgs:
	kfree(sgs);
free_request:
	cleanup_virtio_args(h->op.out, h->op.out_nr);
	cleanup_virtio_args(h->op.in, h->op.in_nr);

	return ret;
}

void virtaccel_clear_req(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h = &req->hdr;

	switch (h->op_type) {
		case VIRTIO_ACCEL_DO_OP:
			cleanup_virtio_args(h->op.out, h->op.out_nr);
			cleanup_virtio_args(h->op.in, h->op.in_nr);
			if (h->op.out_nr)
				kfree(req->sgs[1]);
			if (h->op.in_nr)
				kfree(req->sgs[req->out_sgs]);
			kfree(req->sgs);
		case VIRTIO_ACCEL_CREATE_SESSION:
		case VIRTIO_ACCEL_DESTROY_SESSION:
			kfree((struct accel_session *)req->priv);
			break;
	}

	req->sgs = NULL;
	req->usr = NULL;
	req->out_sgs = 0;
	req->in_sgs = 0;
}

int virtaccel_write_user_output(struct virtio_accel_arg *varg, u32 nr_arg)
{
	int i;

	if (!nr_arg)
		return 0;

	for (i = 0; i < nr_arg; ++i) {
		if (unlikely(copy_to_user(varg[i].usr_buf, varg[i].buf,
					varg[i].len)))
			return -EINVAL;
	}

	return 0;
}

void virtaccel_handle_req_result(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess;
	int ret;

	if (req->status != VIRTIO_ACCEL_OK)
		return;

	switch (h->op_type) {
		case VIRTIO_ACCEL_CREATE_SESSION:
			sess = req->priv;
			ret = virtaccel_write_user_output(h->op.in, h->op.in_nr);
			if (ret) {
				req->ret = -EINVAL;
				return;
			}

			ret = copy_to_user(req->usr, sess, sizeof(*sess));
			if (unlikely(ret)) {
				req->ret = -EINVAL;
				return;
			}

			break;
		case VIRTIO_ACCEL_DESTROY_SESSION:
			break;
		case VIRTIO_ACCEL_DO_OP:
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
