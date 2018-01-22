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
	
	pr_debug("sess keylen: %u, cipher: %d\n", sess->u.crypto.keylen,
				sess->u.crypto.cipher);
	pr_debug("op: %d, keylen: %u, cipher: %d\n", h->op,
				h->u.crypto_sess.keylen, h->u.crypto_sess.cipher);
	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[0] = &hdr_sg;
	sg_init_one(&key_sg, h->u.crypto_sess.key, h->u.crypto_sess.keylen);
	sgs[1] = &key_sg;
	sg_init_one(&sid_sg, &sess->id, sizeof(sess->id));
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

	if (aop->u.crypto.src_len != aop->u.crypto.dst_len) {
		pr_debug("crypto op src_len != dst_len\n");
		h->u.crypto_op.dst = kzalloc_node(aop->u.crypto.dst_len, GFP_ATOMIC,
								dev_to_node(&vaccel->vdev->dev));
		if (!h->u.crypto_op.dst) {
			ret = -ENOMEM;
			goto free_dst;
		}
	} else {
		h->u.crypto_op.dst = h->u.crypto_op.src;
	}

	// TODO: IV
	h->u.crypto_op.iv_len = 0;

	h->u.crypto_op.src_len = cpu_to_virtio32(vdev, aop->u.crypto.src_len);
	h->u.crypto_op.dst_len = cpu_to_virtio32(vdev, aop->u.crypto.dst_len);

	pr_debug("crypto op src_len: %u, dst_len: %u\n", h->u.crypto_op.src_len,
				h->u.crypto_op.dst_len);
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
	kzfree(&h->u.crypto_op.dst);
free:
	kzfree(&h->u.crypto_op.src);
	return ret;
}

int virtaccel_req_gen_create_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, *sg, sid_sg, status_sg, **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	struct accel_gen_op *gen = &sess->u.gen;
	struct accel_gen_op_arg *g_arg = NULL;
	int ret, out_nsgs = 0, in_nsgs = 0, i,
		total_sgs = 3 + gen->in_nr + gen->out_nr;

	h->op = cpu_to_virtio32(vdev, VIRTIO_ACCEL_G_OP_CREATE_SESSION);
	h->u.gen_op.in_nr = cpu_to_virtio32(vdev, gen->in_nr);
	h->u.gen_op.out_nr = cpu_to_virtio32(vdev, gen->out_nr);

	if (h->u.gen_op.in_nr > 0) {
		g_arg = kzalloc_node(gen->in_nr * sizeof(*gen->in),
						GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!g_arg)
			return -ENOMEM;
		
		if (unlikely(copy_from_user(g_arg, gen->in,
							gen->in_nr * sizeof(*gen->in)))) {
			ret = -EFAULT;
			goto free;
		}

		h->u.gen_op.in = kzalloc_node(
								h->u.gen_op.in_nr * sizeof(*h->u.gen_op.in),
								GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!h->u.gen_op.in) {
			ret = -ENOMEM;
			goto free;
		}
		
		for (i = 0; i < gen->in_nr; i++) {
			h->u.gen_op.in[i].len = cpu_to_virtio32(vdev, g_arg[i].len);
			h->u.gen_op.in[i].usr_buf = g_arg[i].buf;
			h->u.gen_op.in[i].buf = kzalloc_node(h->u.gen_op.in[i].len,
											GFP_ATOMIC,
											dev_to_node(&vaccel->vdev->dev));
			if (!h->u.gen_op.in[i].buf) {
				ret = -ENOMEM;
				goto free_in;
			}
			if (unlikely(copy_from_user(h->u.gen_op.in[i].buf, g_arg[i].buf,
								g_arg[i].len))) {
				ret = -EFAULT;
				goto free_in;
			}
		}
		kzfree(g_arg);
	}

	if (h->u.gen_op.out_nr > 0) {
		g_arg = kzalloc_node(gen->out_nr * sizeof(*gen->out),
						GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!g_arg)
			return -ENOMEM;
		
		if (unlikely(copy_from_user(g_arg, gen->out,
							gen->out_nr * sizeof(*gen->out)))) {
			ret = -EFAULT;
			goto free_in;
		}

		h->u.gen_op.out = kzalloc_node(
								h->u.gen_op.out_nr * sizeof(*h->u.gen_op.out),
								GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!h->u.gen_op.out) {
			ret = -ENOMEM;
			goto free_in;
		}
		
		for (i = 0; i < gen->out_nr; i++) {
			h->u.gen_op.out[i].len = cpu_to_virtio32(vdev, g_arg[i].len);
			h->u.gen_op.out[i].usr_buf = g_arg[i].buf;
			h->u.gen_op.out[i].buf = kzalloc_node(h->u.gen_op.out[i].len,
											GFP_ATOMIC,
											dev_to_node(&vaccel->vdev->dev));
			if (!h->u.gen_op.out[i].buf) {
				ret = -ENOMEM;
				goto free_out;
			}
			if (unlikely(copy_from_user(h->u.gen_op.out[i].buf, g_arg[i].buf,
								g_arg[i].len))) {
				ret = -EFAULT;
				goto free_out;
			}
		}
		kzfree(g_arg);
	}

	pr_debug("op: %d, in_nr: %u, out_nr: %u\n",
			h->op, h->u.gen_op.in_nr, h->u.gen_op.out_nr);
	
	sgs = kzalloc_node(total_sgs * sizeof(*sgs), GFP_ATOMIC,
						dev_to_node(&vaccel->vdev->dev));
	if (!sgs) {
		ret = -EFAULT;
		goto free_out;
	}

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[out_nsgs++] = &hdr_sg;
	for (i = 0; i < h->u.gen_op.out_nr; i++) {
		sg = kzalloc_node(sizeof(*sg), GFP_ATOMIC,
						dev_to_node(&vaccel->vdev->dev));
		if (!sg) {
			ret = -ENOMEM;
			goto free_sgs;
		}	
		sg_init_one(sg, h->u.gen_op.out[i].buf, h->u.gen_op.out[i].len);
		sgs[out_nsgs++] = sg;
	}
	for (i = 0; i < h->u.gen_op.out_nr; i++) {
		sg = kzalloc_node(sizeof(*sg), GFP_ATOMIC,
						dev_to_node(&vaccel->vdev->dev));
		if (!sg) {
			ret = -ENOMEM;
			goto free_sgs;
		}	
		sg_init_one(sg, h->u.gen_op.out[i].buf, h->u.gen_op.out[i].len);
		sgs[out_nsgs + in_nsgs++] = sg;
	}
	sg_init_one(&sid_sg, &sess->id, sizeof(sess->id));
	sgs[out_nsgs + in_nsgs++] = &sid_sg;
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[out_nsgs + in_nsgs++] = &status_sg;
	
	req->sgs = sgs;
	req->out_sgs = out_nsgs;
	req->in_sgs = in_nsgs;

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS) {
		in_nsgs--;
		goto free_sgs;
	}

	return ret;

free_sgs:
	for (i = 1; i < (out_nsgs + in_nsgs); i++) {
		if (sgs[i])
			kfree(sgs[i]);
	}
free_out:
	if (h->u.gen_op.out) {
		for (i = 0; i < h->u.gen_op.out_nr; i++) {
			if (h->u.gen_op.out[i].buf)
				kzfree(h->u.gen_op.out[i].buf);
		}
		kfree(h->u.gen_op.out);
	}
free_in:
	if (h->u.gen_op.in) {
		for (i = 0; i < h->u.gen_op.in_nr; i++) {
			if (h->u.gen_op.in[i].buf)
				kzfree(h->u.gen_op.in[i].buf);
		}
		kfree(h->u.gen_op.in);
	}
free:
	if (g_arg)
		kzfree(g_arg);
	return ret;
}

int virtaccel_req_gen_destroy_session(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, status_sg, *sgs[2];
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_session *sess = req->priv;
	int ret;

	h->op = cpu_to_virtio32(vdev, VIRTIO_ACCEL_G_OP_DESTROY_SESSION);
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

int virtaccel_req_gen_operation(struct virtio_accel_req *req)
{
	struct scatterlist hdr_sg, *sg, status_sg, **sgs;
	struct virtio_accel *vaccel = req->vaccel;
	struct virtio_device *vdev = vaccel->vdev;
	struct virtio_accel_hdr *h = &req->hdr;
	struct accel_op *op = req->priv;
	struct accel_gen_op *gen = &op->u.gen;
	struct accel_gen_op_arg *g_arg = NULL;
	int ret, out_nsgs = 0, in_nsgs = 0, i,
		total_sgs = 2 + gen->in_nr + gen->out_nr;

	h->op = cpu_to_virtio32(vdev, VIRTIO_ACCEL_G_OP_DO_OP);
	h->u.gen_op.in_nr = cpu_to_virtio32(vdev, gen->in_nr);
	h->u.gen_op.out_nr = cpu_to_virtio32(vdev, gen->out_nr);

	if (h->u.gen_op.in_nr > 0) {
		g_arg = kzalloc_node(gen->in_nr * sizeof(*gen->in),
						GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!g_arg)
			return -ENOMEM;
		
		if (unlikely(copy_from_user(g_arg, gen->in,
							gen->in_nr * sizeof(*gen->in)))) {
			ret = -EFAULT;
			goto free;
		}

		h->u.gen_op.in = kzalloc_node(
								h->u.gen_op.in_nr * sizeof(*h->u.gen_op.in),
								GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!h->u.gen_op.in) {
			ret = -ENOMEM;
			goto free;
		}
		
		for (i = 0; i < gen->in_nr; i++) {
			h->u.gen_op.in[i].len = cpu_to_virtio32(vdev, g_arg[i].len);
			h->u.gen_op.in[i].usr_buf = g_arg[i].buf;
			h->u.gen_op.in[i].buf = kzalloc_node(h->u.gen_op.in[i].len,
											GFP_ATOMIC,
											dev_to_node(&vaccel->vdev->dev));
			if (!h->u.gen_op.in[i].buf) {
				ret = -ENOMEM;
				goto free_in;
			}
			if (unlikely(copy_from_user(h->u.gen_op.in[i].buf, g_arg[i].buf,
								g_arg[i].len))) {
				ret = -EFAULT;
				goto free_in;
			}
		}
		kfree(g_arg);
	}

	if (h->u.gen_op.out_nr > 0) {
		g_arg = kzalloc_node(gen->out_nr * sizeof(*gen->out),
						GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!g_arg)
			return -ENOMEM;
		
		if (unlikely(copy_from_user(g_arg, gen->out,
							gen->out_nr * sizeof(*gen->out)))) {
			ret = -EFAULT;
			goto free_in;
		}

		h->u.gen_op.out = kzalloc_node(
								h->u.gen_op.out_nr * sizeof(*h->u.gen_op.out),
								GFP_ATOMIC, dev_to_node(&vaccel->vdev->dev));
		if (!h->u.gen_op.out) {
			ret = -ENOMEM;
			goto free_in;
		}
		
		for (i = 0; i < gen->out_nr; i++) {
			h->u.gen_op.out[i].len = cpu_to_virtio32(vdev, g_arg[i].len);
			h->u.gen_op.out[i].usr_buf = g_arg[i].buf;
			h->u.gen_op.out[i].buf = kzalloc_node(h->u.gen_op.out[i].len,
											GFP_ATOMIC,
											dev_to_node(&vaccel->vdev->dev));
			if (!h->u.gen_op.out[i].buf) {
				ret = -ENOMEM;
				goto free_out;
			}
			if (unlikely(copy_from_user(h->u.gen_op.out[i].buf, g_arg[i].buf,
								g_arg[i].len))) {
				ret = -EFAULT;
				goto free_out;
			}
		}
		kfree(g_arg);
	}

	pr_debug("op: %d, in_nr: %u, out_nr: %u\n",
			h->op, h->u.gen_op.in_nr, h->u.gen_op.out_nr);
	
	sgs = kzalloc_node(total_sgs * sizeof(*sgs), GFP_ATOMIC,
						dev_to_node(&vaccel->vdev->dev));
	if (!sgs) {
		ret = -EFAULT;
		goto free_out;
	}

	sg_init_one(&hdr_sg, h, sizeof(*h));
	sgs[out_nsgs++] = &hdr_sg;
	for (i = 0; i < h->u.gen_op.out_nr; i++) {
		sg = kzalloc_node(sizeof(*sg), GFP_ATOMIC,
						dev_to_node(&vaccel->vdev->dev));
		if (!sg) {
			ret = -ENOMEM;
			goto free_sgs;
		}	
		sg_init_one(sg, h->u.gen_op.out[i].buf, h->u.gen_op.out[i].len);
		sgs[out_nsgs++] = sg;
	}
	for (i = 0; i < h->u.gen_op.out_nr; i++) {
		sg = kzalloc_node(sizeof(*sg), GFP_ATOMIC,
						dev_to_node(&vaccel->vdev->dev));
		if (!sg) {
			ret = -ENOMEM;
			goto free_sgs;
		}	
		sg_init_one(sg, h->u.gen_op.out[i].buf, h->u.gen_op.out[i].len);
		sgs[out_nsgs + in_nsgs++] = sg;
	}
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[out_nsgs + in_nsgs++] = &status_sg;
	
	req->sgs = sgs;
	req->out_sgs = out_nsgs;
	req->in_sgs = in_nsgs;

	ret = virtaccel_do_req(req);
	if (ret != -EINPROGRESS) {
		in_nsgs--;
		goto free_sgs;
	}

	return ret;

free_sgs:
	for (i = 1; i < (out_nsgs + in_nsgs); i++) {
		if (sgs[i])
			kfree(sgs[i]);
	}
free_out:
	if (h->u.gen_op.out) {
		for (i = 0; i < h->u.gen_op.out_nr; i++) {
			if (h->u.gen_op.out[i].buf)
				kzfree(h->u.gen_op.out[i].buf);
		}
		kfree(h->u.gen_op.out);
	}
free_in:
	if (h->u.gen_op.in) {
		for (i = 0; i < h->u.gen_op.in_nr; i++) {
			if (h->u.gen_op.in[i].buf)
				kzfree(h->u.gen_op.in[i].buf);
		}
		kfree(h->u.gen_op.in);
	}
free:
	if (g_arg)
		kzfree(g_arg);
	return ret;
}

void virtaccel_clear_req(struct virtio_accel_req *req)
{
	struct virtio_accel_hdr *h = &req->hdr;
	int i;
	
	switch (h->op) {
	case VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION:
		kzfree(h->u.crypto_sess.key);
	case VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION:
		kzfree((struct accel_session *)req->priv);
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT:
	case VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT:
		if (h->u.crypto_op.src != h->u.crypto_op.dst)
			kzfree(h->u.crypto_op.dst);
		kzfree(h->u.crypto_op.src);
		kzfree((struct accel_op *)req->priv);
		break;
	case VIRTIO_ACCEL_G_OP_CREATE_SESSION:
		if (h->u.gen_op.out) {
			for (i = 0; i < h->u.gen_op.out_nr; i++) {
				if (h->u.gen_op.out[i].buf)
					kzfree(h->u.gen_op.out[i].buf);
			}
			kfree(h->u.gen_op.out);
		}
		if (h->u.gen_op.in) {
			for (i = 0; i < h->u.gen_op.in_nr; i++) {
				if (h->u.gen_op.in[i].buf)
					kzfree(h->u.gen_op.in[i].buf);
			}
			kfree(h->u.gen_op.in);
		}
		for (i = 1; i < (req->out_sgs + req->in_sgs - 2); i++) {
			if (req->sgs[i])
				kfree(req->sgs[i]);
		}
		kfree(req->sgs);
	case VIRTIO_ACCEL_G_OP_DESTROY_SESSION:
		kzfree((struct accel_session *)req->priv);
		break;
	case VIRTIO_ACCEL_G_OP_DO_OP:
		if (h->u.gen_op.out) {
			for (i = 0; i < h->u.gen_op.out_nr; i++) {
				if (h->u.gen_op.out[i].buf)
					kzfree(h->u.gen_op.out[i].buf);
			}
			kfree(h->u.gen_op.out);
		}
		if (h->u.gen_op.in) {
			for (i = 0; i < h->u.gen_op.in_nr; i++) {
				if (h->u.gen_op.in[i].buf)
					kzfree(h->u.gen_op.in[i].buf);
			}
			kfree(h->u.gen_op.in);
		}
		for (i = 1; i < (req->out_sgs + req->in_sgs - 1); i++) {
			if (req->sgs[i])
				kfree(req->sgs[i]);
		}
		kfree(req->sgs);
		kzfree((struct accel_op *)req->priv);
		break;
	default:
		pr_err("clear req: invalid op returned\n");
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
	struct accel_session *sess;
	struct accel_op *op;
	int i;

	if (req->status != VIRTIO_ACCEL_OK)
		return;

	switch (h->op) {
	case VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION:
		sess = req->priv;
		if (unlikely(copy_to_user(req->usr, sess, sizeof(*sess)))) {
			pr_err("handle req: create crypto session copy failed\n");
			req->status = VIRTIO_ACCEL_ERR;
			return;
		}
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION:
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT:
	case VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT:
		op = req->priv;
		if (unlikely(copy_to_user(op->u.crypto.dst, h->u.crypto_op.dst,
						h->u.crypto_op.dst_len))) {
			pr_err("handle req: crypto op copy failed\n");
			req->status = VIRTIO_ACCEL_ERR;
			return;
		}
		break;
	case VIRTIO_ACCEL_G_OP_CREATE_SESSION:
		if (h->u.gen_op.in) {
			for (i = 0; i < h->u.gen_op.in_nr; i++) {
				if (!h->u.gen_op.in[i].buf)
					continue;
				if (unlikely(copy_to_user(h->u.gen_op.in[i].usr_buf,
									h->u.gen_op.in[i].buf,
									h->u.gen_op.in[i].len))) {
					pr_err("handle req: create generic session arg copy failed"
							"\n");
					req->status = VIRTIO_ACCEL_ERR;
					return;
				}
			}
		}
		sess = req->priv;
		if (unlikely(copy_to_user(req->usr, sess, sizeof(*sess)))) {
			pr_err("handle req: create generic session copy failed\n");
			req->status = VIRTIO_ACCEL_ERR;
			return;
		}
		break;
	case VIRTIO_ACCEL_G_OP_DESTROY_SESSION:
		break;
	case VIRTIO_ACCEL_G_OP_DO_OP:
		if (h->u.gen_op.in) {
			for (i = 0; i < h->u.gen_op.in_nr; i++) {
				if (!h->u.gen_op.in[i].buf)
					continue;
				if (unlikely(copy_to_user(h->u.gen_op.in[i].usr_buf,
									h->u.gen_op.in[i].buf,
									h->u.gen_op.in[i].len))) {
					pr_err("handle req: create generic session arg copy failed"
							"\n");
					req->status = VIRTIO_ACCEL_ERR;
					return;
				}
			}
		}
		op = req->priv;
		if (unlikely(copy_to_user(op->u.gen.in, h->u.gen_op.in,
						sizeof(*h->u.gen_op.in)))) {
			pr_err("handle req: op copy failed\n");
			req->status = VIRTIO_ACCEL_ERR;
			return;
		}
		break;
	default:
		pr_err("hadle req: invalid op returned\n");
		break;
	}
}

int virtaccel_do_req(struct virtio_accel_req *req)
{
	struct virtio_accel *va = req->vaccel;
	int ret, i, total_sg = 0;
	unsigned long flags;

	init_completion(&req->completion);
/*
 	for (i = 0; i < req->out_sgs + req->in_sgs; i++) {
        struct scatterlist *sg;
        for (sg = req->sgs[i]; sg; sg = sg_next(sg))
            total_sg++;
    }
	pr_debug("TOTAL SGS: %u\n", total_sg);
*/
	// select vq[0] explicitly for now
	spin_lock_irqsave(&va->vq[0].lock, flags);
	ret = virtqueue_add_sgs(va->vq[0].vq, req->sgs, req->out_sgs,
			req->in_sgs, req, GFP_ATOMIC);
	virtqueue_kick(va->vq[0].vq);
	spin_unlock_irqrestore(&va->vq[0].lock, flags);
	pr_debug("do_req ret: %d\n", ret);
	if (unlikely(ret < 0)) {
		// TODO: free key etc.
		virtaccel_clear_req(req);
		return ret;
	}

	return -EINPROGRESS;
}
