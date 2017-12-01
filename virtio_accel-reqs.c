#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <linux/err.h>
#include <crypto/scatterwalk.h>
#include <linux/atomic.h>

#include "accel.h"
#include "virtio_accel.h"


int virtio_accel_req_create_session(virtio_accel_request *req)
{
	struct scatterlist hdr_sg, key_sg, sid_sg, status_sg, **sgs;
	struct virtio_accel_header *h = &req->header;
	struct accel_session *sess = req->priv[1];

	// TODO: check op
	h->op = cpu_to_le32(sess->op);
	h->session_id = 0;

	h->u.crypto_op.key = kzalloc_node(sizeof(*h->u.crypto_op.key), GFP_ATOMIC,
								dev_to_node(&vcrypto->vdev->dev));
	if (!h->crypto_op.key)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(&h->u.crypto_op.key, sess->u.crypto_op.key, 
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

	h->u.crypto_op.cipher = cpu_to_le32(sess->u.crypto_op.cipher);
	h->u.crypto_op.keylen = cpu_to_le32(sess->u.crypto_op.keylen);

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&key_sg, h->u.crypto_op.key, sizeof(h->u.crypto_op.keylen));
	sgs[1] = &key_sg;
	sg_init_one(&sid_sg, &sess->id, sizeof(sess->id));
	sgs[2] = &sid_sg;
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[3] = &status_sg;

	req->vaccel = vaccel;
	req->sgs = sgs;
	req->out_sgs = 2;
	req->in_sgs = 2;

	return 0;

free:
	kfree(&h->u.crypto_op.key);
	return ret;
}

int virtio_accel_do_req(virtio_accel_request *req)
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
