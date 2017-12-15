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
	struct scatterlist hdr_sg, key_sg, sid_sg, status_sg, *sgs[4];
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;

	h->op = cpu_to_virtio32(vdev, VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION);

	h->u.crypto_sess.key = kzalloc_node(sess->u.crypto.keylen,
								GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
	if (!h->u.crypto_sess.key)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(h->u.crypto_sess.key, sess->u.crypto.key, 
								sess->u.crypto.keylen))) {
		ret = -EFAULT;
		goto free;
	}

	h->u.crypto_sess.cipher = cpu_to_virtio32(vdev, sess->u.crypto.cipher);
	h->u.crypto_sess.keylen = cpu_to_virtio32(vdev, sess->u.crypto.keylen);
	
	pr_debug("op: %d, keylen: %u, cipher: %d\n", h->op,
				 h->u.crypto_sess.keylen, h->u.crypto_sess.cipher);
	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&key_sg, h->u.crypto_sess.key, h->u.crypto_sess.keylen);
	sgs[1] = &key_sg;
	sg_init_one(&sid_sg, &h->session_id, sizeof(h->session_id));
	sgs[2] = &sid_sg;
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[3] = &status_sg;
	
	req->sgs = sgs;
	req->out_sgs = 2;
	req->in_sgs = 2;

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		goto free;

	req->sgs = NULL;
	return ret;

free:
	kzfree(h->u.crypto_sess.key);
	return ret;
}

int virtaccel_req_crypto_destroy_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, status_sg, *sgs[2];
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;

	h->op = cpu_to_virtio32(vdev, VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION);
	h->session_id = cpu_to_virtio32(vdev, sess->id);

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[1] = &status_sg;

	req->sgs = sgs;
	req->out_sgs = 1;
	req->in_sgs = 1;

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		goto free;
	
	req->sgs = NULL;
	return ret;

free:
	return ret;
}

int virtaccel_req_crypto_operation(struct virtio_accel_req *req, int opcode)
{
	struct scatterlist hdr_sg, src_sg, dst_sg, iv_sg, status_sg, *sgs[4];
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op *aop = req->priv;
	int ret;

	h->op = cpu_to_virtio32(vdev, opcode);
	h->session_id = cpu_to_virtio32(vdev, aop->session_id);

	h->u.crypto_op.src = kzalloc_node(aop->u.crypto.src_len, GFP_ATOMIC,
								dev_to_node(&vaccel->vdev->dev));
	if (!h->u.crypto_op.src)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(h->u.crypto_op.src, aop->u.crypto.src, 
								aop->u.crypto.src_len))) {
		ret = -EFAULT;
		goto free;
	}

	if (aop->u.crypto.src != aop->u.crypto.dst) {
		h->u.crypto_op.dst = kzalloc_node(aop->u.crypto.dst_len, GFP_ATOMIC,
								dev_to_node(&vaccel->vdev->dev));
		if (!h->u.crypto_op.dst) {
			ret = -ENOMEM;
			goto free;
		}
		
		if (unlikely(copy_from_user(h->u.crypto_op.dst, aop->u.crypto.dst, 
									aop->u.crypto.dst_len))) {
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
	sg_init_one(&src_sg, h->u.crypto_op.src, h->u.crypto_op.src_len);
	sgs[1] = &src_sg;
	sg_init_one(&dst_sg, h->u.crypto_op.dst, h->u.crypto_op.dst_len);
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

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS)
		goto free;
	
	req->sgs = NULL;
	return ret;

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
		kzfree(sess);
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION:
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT:
	case VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT:
		op = req->priv;
		if (unlikely(copy_to_user(op->u.crypto.dst, h->u.crypto_op.dst,
						h->u.crypto_op.dst_len))) {
			kzfree(op);
			req->status = VIRTIO_ACCEL_ERR;
			goto out;
		}
		kzfree(op);
		break;
	}

out:
	virtaccel_clear_req(req);
}

int virtaccel_do_req(struct virtio_accel_req *req)
{
	struct virtio_accel *va = req->vaccel;
	int ret, i, total_sg = 0;
	unsigned long flags;

	pr_debug("do_req 1\n");
	init_completion(&req->completion);

	pr_debug("do_req 2, out:%u in:%u\n", req->out_sgs, req->in_sgs);
 	for (i = 0; i < req->out_sgs + req->in_sgs; i++) {
        struct scatterlist *sg;
        for (sg = req->sgs[i]; sg; sg = sg_next(sg))
            total_sg++;
    }
	pr_debug("TOTAL SGS: %u\n", total_sg);

	// select vq[0] explicitly for now
	spin_lock_irqsave(&va->vq[0].lock, flags);
	pr_debug("do_req 3\n");
	ret = virtqueue_add_sgs(va->vq[0].vq, req->sgs, req->out_sgs,
			req->in_sgs, req, GFP_ATOMIC);
	pr_debug("do_req 4\n");
	virtqueue_kick(va->vq[0].vq);
	pr_debug("do_req 5\n");
	spin_unlock_irqrestore(&va->vq[0].lock, flags);
	pr_debug("do_req 6 : %d\n", ret);
	if (unlikely(ret < 0)) {
		// TODO: free key etc.
		req->out_sgs = 0;
		req->in_sgs = 0;
		return ret;
	}

	return -EINPROGRESS;
}
