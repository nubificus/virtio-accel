#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <linux/err.h>
#include <crypto/scatterwalk.h>
#include <linux/atomic.h>

#include "accel.h"
#include "virtio_accel.h"


int virtaccel_req_crypto_create_session(virtio_accel_request *req)
{
	struct scatterlist hdr_sg, key_sg, sid_sg, status_sg, **sgs;
	struct virtio_accel_header *h = &req->header;
	struct accel_session *sess = req->priv[1];

	h->op = virtio32_to_cpu(VIRTIO_ACCEL_CRYPTO_CIPHER_CREATE_SESSION);

	h->u.crypto_sess.key = kzalloc_node(sizeof(*h->u.crypto_sess.key), GFP_ATOMIC,
								dev_to_node(&vcrypto->vdev->dev));
	if (!h->crypto.key)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(&h->u.crypto_sess.key, sess->u.crypto.key, 
								sizeof(sess))))
		ret = -EFAULT;
		goto free;
	}

	sgs = kzalloc_node(4 * sizeof(*sgs), GFP_ATOMIC,
				dev_to_node(&vcrypto->vdev->dev));
	if (!sgs) {
	   ret = -ENOMEM;
	   goto free;
	}

	h->u.crypto_sess.cipher = virtio32_to_cpu(sess->u.crypto.cipher);
	h->u.crypto_sess.keylen = virtio32_to_cpu(sess->u.crypto.keylen);

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

int virtaccel_req_crypto_encrypt(virtio_accel_request *req)
{
	struct scatterlist hdr_sg, src_sg, iv_sg, status_sg, **sgs;
	struct virtio_accel_header *h = &req->header;
	struct accel_op *aop = req->priv;


	
	h->op = virtio32_to_cpu(VIRTIO_ACCEL_CRYPTO_CIPHER_ENCRYPT);
	h->session_id = virtio32_to_cpu(aop->session_id);

	h->u.crypto_op.src = kzalloc_node(sizeof(*h->u.crypto_op.src), GFP_ATOMIC,
								dev_to_node(&vcrypto->vdev->dev));
	if (!h->crypto_op.src)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(&h->u.crypto_op.src, aop->u.crypto.src, 
								sizeof(sess))))
		ret = -EFAULT;
		goto free;
	}

	// TODO: IV
	h->u.crypto_op.ivlen = 0;

	sgs = kzalloc_node(3 * sizeof(*sgs), GFP_ATOMIC,
				dev_to_node(&vcrypto->vdev->dev));
	if (!sgs) {
	   ret = -ENOMEM;
	   goto free;
	}

	h->u.crypto_op.src_len = virtio32_to_cpu(aop->u.crypto.src_len);

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&src_sg, h->u.crypto_op.src, sizeof(h->u.crypto_op.src_len));
	sgs[1] = &src_sg;
	/*
	sg_init_one(&iv_sg, h->u.crypto_op.iv, sizeof(h->u.crypto_op.iv_len));
	sgs[2] = &iv_sg;
	*/
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[2] = &status_sg;

	req->sgs = sgs;
	req->out_sgs = 2;
	req->in_sgs = 1;

	return 0;

free:
	kfree(&h->u.crypto_op.src);
	return ret;
}

int virtaccel_do_req(virtio_accel_request *req)
{
	virtio_accel *va = req->vaccel;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(va->vq_lock, flags);
	ret = virtqueue_add_sgs(va->vq, sgs, va->out_sgs,
			va->in_sgs, req, GFP_ATOMIC);
	virtqueue_kick(va->vq_lock);
	spin_unlock_irqrestore(va->vq_lock, flags);
	if (unlikely(ret < 0)) {
		// TODO: free key etc.
		kfree(req->sgs);
		req->out_sgs = 0;
		req->in_sgs = 0;
		return ret;
	}

	return 0;
}
