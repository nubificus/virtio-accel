#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <linux/err.h>
#include <crypto/scatterwalk.h>
#include <linux/atomic.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "accel.h"
#include "virtio_accel-common.h"


int virtaccel_req_crypto_create_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, key_sg, sid_sg, status_sg, **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;

	sgs = kzalloc_node(4 * sizeof(*sgs), GFP_ATOMIC,
				dev_to_node(&vaccel->vdev->dev));
	if (!sgs)
	   return -ENOMEM;

	h->op = cpu_to_virtio32(vdev, VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION);

	h->u.crypto_sess.key = kzalloc_node(sizeof(*h->u.crypto_sess.key),
								GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
	if (!h->u.crypto_sess.key)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(&h->u.crypto_sess.key, sess->u.crypto.key, 
								sizeof(sess)))) {
		ret = -EFAULT;
		goto free;
	}

	h->u.crypto_sess.cipher = cpu_to_virtio32(vdev, sess->u.crypto.cipher);
	h->u.crypto_sess.keylen = cpu_to_virtio32(vdev, sess->u.crypto.keylen);

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&key_sg, h->u.crypto_sess.key, sizeof(h->u.crypto_sess.keylen));
	sgs[1] = &key_sg;
	sg_init_one(&sid_sg, &sess->id, sizeof(sess->id));
	sgs[2] = &sid_sg;
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[3] = &status_sg;

	req->sgs = sgs;
	req->out_sgs = 2;
	req->in_sgs = 2;

	return 0;

free:
	kfree(&h->u.crypto_sess.key);
	return ret;
}

int virtaccel_req_crypto_destroy_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, status_sg, **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;

	sgs = kzalloc_node(2 * sizeof(*sgs), GFP_ATOMIC,
				dev_to_node(&vaccel->vdev->dev));
	if (!sgs)
	   return -ENOMEM;

	h->op = cpu_to_virtio32(vdev, VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION);
	h->session_id = cpu_to_virtio32(vdev, sess->id);

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[1] = &status_sg;

	req->sgs = sgs;
	req->out_sgs = 1;
	req->in_sgs = 1;

	return 0;

free:
	return ret;
}

int virtaccel_req_crypto_operation(struct virtio_accel_req *req, int opcode)
{
	struct scatterlist hdr_sg, src_sg, dst_sg, iv_sg, status_sg, **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op *aop = req->priv;
	int ret;

	sgs = kzalloc_node(4 * sizeof(*sgs), GFP_ATOMIC,
				dev_to_node(&vaccel->vdev->dev));
	if (!sgs)
	   return -ENOMEM;

	h->op = cpu_to_virtio32(vdev, opcode);
	h->session_id = cpu_to_virtio32(vdev, aop->session_id);

	h->u.crypto_op.src = kzalloc_node(sizeof(*h->u.crypto_op.src), GFP_ATOMIC,
								dev_to_node(&vaccel->vdev->dev));
	if (!h->u.crypto_op.src)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(&h->u.crypto_op.src, aop->u.crypto.src, 
								sizeof(aop->u.crypto.src_len)))) {
		ret = -EFAULT;
		goto free;
	}

	if (aop->u.crypto.src != aop->u.crypto.dst) {
		h->u.crypto_op.dst = kzalloc_node(sizeof(*h->u.crypto_op.dst), 
								GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!h->u.crypto_op.dst) {
			ret = -ENOMEM;
			goto free;
		}
		
		if (unlikely(copy_from_user(&h->u.crypto_op.dst, aop->u.crypto.dst, 
									sizeof(aop->u.crypto.dst_len)))) {
			ret = -EFAULT;
			goto free_dst;
		}
	}

	// TODO: IV
	h->u.crypto_op.iv_len = 0;

	h->u.crypto_op.src_len = cpu_to_virtio32(vdev, aop->u.crypto.src_len);
	h->u.crypto_op.dst_len = cpu_to_virtio32(vdev, aop->u.crypto.dst_len);

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&src_sg, h->u.crypto_op.src, sizeof(h->u.crypto_op.src_len));
	sgs[1] = &src_sg;
	sg_init_one(&dst_sg, h->u.crypto_op.dst, sizeof(h->u.crypto_op.dst_len));
	sgs[2] = &dst_sg;
	/*
	sg_init_one(&iv_sg, h->u.crypto_op.iv, sizeof(h->u.crypto_op.iv_len));
	sgs[3] = &iv_sg;
	*/
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[3] = &status_sg;

	req->sgs = sgs;
	req->out_sgs = 2;
	req->in_sgs = 2;

	return 0;

free_dst:
	kfree(&h->u.crypto_op.dst);
free:
	kfree(&h->u.crypto_op.src);
	return ret;
}

void virtaccel_clear_req(struct virtio_accel_req *req)
{
	if (req) {
		kzfree(req->vaccel);
		kfree(req->sgs);
	}
}

void virtaccel_handle_req_result(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess;
	struct accel_op *op;

	if (req->status != VIRTIO_ACCEL_OK)
		goto out;

	switch (req->hdr.op) {
	case VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION:
		sess = req->priv;
		if (unlikely(copy_to_user(req->usr, sess, sizeof(*sess)))) {
			kfree(sess);
			req->status = VIRTIO_ACCEL_ERR;
			goto out;
		}
		kfree(sess);
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION:
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT:
	case VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT:
		op = req->priv;
		if (unlikely(copy_to_user(op->u.crypto.dst, h->u.crypto_op.dst,
						h->u.crypto_op.dst_len))) {
			kfree(op);
			req->status = VIRTIO_ACCEL_ERR;
			goto out;
		}
		kfree(op);
		break;
	}

out:
	virtaccel_clear_req(req);
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
		// TODO: free key etc.
		kfree(req->sgs);
		req->out_sgs = 0;
		req->in_sgs = 0;
		return ret;
	}

	return -EINPROGRESS;
}
