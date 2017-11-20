 /* Algorithms supported by virtio crypto device
  *
  * Authors: Gonglei <arei.gonglei@huawei.com>
  *
  * Copyright 2016 HUAWEI TECHNOLOGIES CO., LTD.
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, see <http://www.gnu.org/licenses/>.
  */

#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <linux/err.h>
#include <crypto/scatterwalk.h>
#include <linux/atomic.h>

#include "virtio_crypto.h"
#include "virtio_crypto_common.h"


//struct timespec ts1;

/*
 * The algs_lock protects the below global virtio_crypto_active_devs
 * and crypto algorithms registion.
 */
static DEFINE_MUTEX(algs_lock);
static unsigned int virtio_crypto_active_devs;

static u64 virtio_crypto_alg_sg_nents_length(struct scatterlist *sg)
{
	u64 total = 0;

	for (total = 0; sg; sg = sg_next(sg))
		total += sg->length;

	return total;
}

static int
virtio_crypto_alg_validate_key(int key_len, uint32_t *alg)
{
	switch (key_len) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		//*alg = VIRTIO_CRYPTO_CIPHER_AES_CBC;
		*alg = VIRTIO_CRYPTO_CIPHER_AES_ECB;
		break;
	default:
		pr_err("virtio_crypto: Unsupported key length: %d\n",
			key_len);
		return -EINVAL;
	}
	return 0;
}

static int virtio_crypto_alg_ablkcipher_init_session(
		struct virtio_crypto_ablkcipher_ctx *ctx,
		uint32_t alg, const uint8_t *key,
		unsigned int keylen,
		int encrypt)
{
	struct scatterlist outhdr, key_sg, inhdr, *sgs[3];
	unsigned int tmp;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int op = encrypt ? VIRTIO_CRYPTO_OP_ENCRYPT : VIRTIO_CRYPTO_OP_DECRYPT;
	int err;
	unsigned int num_out = 0, num_in = 0;

	/*
	 * Avoid to do DMA from the stack, switch to using
	 * dynamically-allocated for the key
	 */
	uint8_t *cipher_key = kmalloc(keylen, GFP_ATOMIC);

	if (!cipher_key)
		return -ENOMEM;

	memcpy(cipher_key, key, keylen);

	spin_lock(&vcrypto->ctrl_lock);
	/* Pad ctrl header */
	vcrypto->ctrl.header.opcode =
		cpu_to_le32(VIRTIO_CRYPTO_CIPHER_CREATE_SESSION);
	vcrypto->ctrl.header.algo = cpu_to_le32(alg);
	/* Set the default dataqueue id to 0 */
	vcrypto->ctrl.header.queue_id = 0;

	vcrypto->input.status = cpu_to_le32(VIRTIO_CRYPTO_ERR);
	/* Pad cipher's parameters */
	vcrypto->ctrl.u.sym_create_session.op_type =
		cpu_to_le32(VIRTIO_CRYPTO_SYM_OP_CIPHER);
	vcrypto->ctrl.u.sym_create_session.u.cipher.para.algo =
		vcrypto->ctrl.header.algo;
	vcrypto->ctrl.u.sym_create_session.u.cipher.para.keylen =
		cpu_to_le32(keylen);
	vcrypto->ctrl.u.sym_create_session.u.cipher.para.op =
		cpu_to_le32(op);

	sg_init_one(&outhdr, &vcrypto->ctrl, sizeof(vcrypto->ctrl));
	sgs[num_out++] = &outhdr;

	/* Set key */
	sg_init_one(&key_sg, cipher_key, keylen);
	sgs[num_out++] = &key_sg;

	/* Return status and session id back */
	sg_init_one(&inhdr, &vcrypto->input, sizeof(vcrypto->input));
	sgs[num_out + num_in++] = &inhdr;

	err = virtqueue_add_sgs(vcrypto->ctrl_vq, sgs, num_out,
				num_in, vcrypto, GFP_ATOMIC);
	if (err < 0) {
		spin_unlock(&vcrypto->ctrl_lock);
		kzfree(cipher_key);
		return err;
	}
	virtqueue_kick(vcrypto->ctrl_vq);

	/*
	 * Trapping into the hypervisor, so the request should be
	 * handled immediately.
	 */
	while (!virtqueue_get_buf(vcrypto->ctrl_vq, &tmp) &&
	       !virtqueue_is_broken(vcrypto->ctrl_vq))
		cpu_relax();

	if (le32_to_cpu(vcrypto->input.status) != VIRTIO_CRYPTO_OK) {
		spin_unlock(&vcrypto->ctrl_lock);
		pr_err("virtio_crypto: Create session failed status: %u\n",
			le32_to_cpu(vcrypto->input.status));
		kzfree(cipher_key);
		return -EINVAL;
	}

	if (encrypt)
		ctx->enc_sess_info.session_id =
			le64_to_cpu(vcrypto->input.session_id);
	else
		ctx->dec_sess_info.session_id =
			le64_to_cpu(vcrypto->input.session_id);

	spin_unlock(&vcrypto->ctrl_lock);

	kzfree(cipher_key);
	return 0;
}

static int virtio_crypto_alg_ablkcipher_close_session(
		struct virtio_crypto_ablkcipher_ctx *ctx,
		int encrypt)
{
	struct scatterlist outhdr, status_sg, *sgs[2];
	unsigned int tmp;
	struct virtio_crypto_destroy_session_req *destroy_session;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int err;
	unsigned int num_out = 0, num_in = 0;

	spin_lock(&vcrypto->ctrl_lock);
	vcrypto->ctrl_status.status = VIRTIO_CRYPTO_ERR;
	/* Pad ctrl header */
	vcrypto->ctrl.header.opcode =
		cpu_to_le32(VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION);
	/* Set the default virtqueue id to 0 */
	vcrypto->ctrl.header.queue_id = 0;

	destroy_session = &vcrypto->ctrl.u.destroy_session;

	if (encrypt)
		destroy_session->session_id =
			cpu_to_le64(ctx->enc_sess_info.session_id);
	else
		destroy_session->session_id =
			cpu_to_le64(ctx->dec_sess_info.session_id);

	sg_init_one(&outhdr, &vcrypto->ctrl, sizeof(vcrypto->ctrl));
	sgs[num_out++] = &outhdr;

	/* Return status and session id back */
	sg_init_one(&status_sg, &vcrypto->ctrl_status.status,
		sizeof(vcrypto->ctrl_status.status));
	sgs[num_out + num_in++] = &status_sg;

	err = virtqueue_add_sgs(vcrypto->ctrl_vq, sgs, num_out,
			num_in, vcrypto, GFP_ATOMIC);
	if (err < 0) {
		spin_unlock(&vcrypto->ctrl_lock);
		return err;
	}
	virtqueue_kick(vcrypto->ctrl_vq);

	while (!virtqueue_get_buf(vcrypto->ctrl_vq, &tmp) &&
	       !virtqueue_is_broken(vcrypto->ctrl_vq))
		cpu_relax();

	if (vcrypto->ctrl_status.status != VIRTIO_CRYPTO_OK) {
		spin_unlock(&vcrypto->ctrl_lock);
		pr_err("virtio_crypto: Close session failed status: %u, session_id: 0x%llx\n",
			vcrypto->ctrl_status.status,
			destroy_session->session_id);

		return -EINVAL;
	}
	spin_unlock(&vcrypto->ctrl_lock);

	return 0;
}

static int virtio_crypto_alg_ablkcipher_init_sessions(
		struct virtio_crypto_ablkcipher_ctx *ctx,
		const uint8_t *key, unsigned int keylen)
{
	uint32_t alg;
	int ret;
	struct virtio_crypto *vcrypto = ctx->vcrypto;

	if (keylen > vcrypto->max_cipher_key_len) {
		pr_err("virtio_crypto: the key is too long\n");
		goto bad_key;
	}

	if (virtio_crypto_alg_validate_key(keylen, &alg))
		goto bad_key;

	/* Create encryption session */
	ret = virtio_crypto_alg_ablkcipher_init_session(ctx,
			alg, key, keylen, 1);
	if (ret)
		return ret;
	/* Create decryption session */
	ret = virtio_crypto_alg_ablkcipher_init_session(ctx,
			alg, key, keylen, 0);
	if (ret) {
		virtio_crypto_alg_ablkcipher_close_session(ctx, 1);
		return ret;
	}
	return 0;

bad_key:
	crypto_tfm_set_flags(ctx->tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

/* Note: kernel crypto API realization */
static int virtio_crypto_ablkcipher_setkey(struct crypto_ablkcipher *tfm,
					 const uint8_t *key,
					 unsigned int keylen)
{
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	int ret;

	if (!ctx->vcrypto) {
		/* New key */
		int node = virtio_crypto_get_current_node();
		struct virtio_crypto *vcrypto =
				      virtcrypto_get_dev_node(node);
		if (!vcrypto) {
			pr_err("virtio_crypto: Could not find a virtio device in the system");
			return -ENODEV;
		}

		ctx->vcrypto = vcrypto;
	} else {
		/* Rekeying, we should close the created sessions previously */
		virtio_crypto_alg_ablkcipher_close_session(ctx, 1);
		virtio_crypto_alg_ablkcipher_close_session(ctx, 0);
	}

	ret = virtio_crypto_alg_ablkcipher_init_sessions(ctx, key, keylen);
	if (ret) {
		virtcrypto_dev_put(ctx->vcrypto);
		ctx->vcrypto = NULL;

		return ret;
	}

	return 0;
}

static int
__virtio_crypto_ablkcipher_do_req(struct virtio_crypto_request *vc_req,
		struct ablkcipher_request *req,
		struct data_queue *data_vq,
		__u8 op)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	unsigned int ivsize = crypto_ablkcipher_ivsize(tfm);
	struct virtio_crypto_ablkcipher_ctx *ctx = vc_req->ablkcipher_ctx;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	struct virtio_crypto_op_data_req *req_data;
	int src_nents, dst_nents, sg_total;
	int err;
	unsigned long flags;
	struct scatterlist outhdr, iv_sg, status_sg, **sgs, *sg, out_sg;
	int i;
	u64 dst_len;
	unsigned int num_out = 0, num_in = 0, sg_len;
	size_t sg_bytes, offset, total_bytes;
	uint8_t *iv = NULL;
	void *buf = NULL;

	src_nents = sg_nents_for_len(req->src, req->nbytes);
	dst_nents = sg_nents(req->dst);

	pr_debug("virtio_crypto: Number of sgs (src_nents: %d, dst_nents: %d)\n",
			src_nents, dst_nents);

	/* Why 3?  outhdr + iv + inhdr */
	sg_total = src_nents + dst_nents + 3;
	sgs = kzalloc_node(sg_total * sizeof(*sgs), GFP_ATOMIC,
				dev_to_node(&vcrypto->vdev->dev));
	if (!sgs)
		return -ENOMEM;

	req_data = kzalloc_node(sizeof(*req_data), GFP_ATOMIC,
				dev_to_node(&vcrypto->vdev->dev));
	if (!req_data) {
		kfree(sgs);
		return -ENOMEM;
	}

	vc_req->req_data = req_data;
	vc_req->type = VIRTIO_CRYPTO_SYM_OP_CIPHER;
	/* Head of operation */
	if (op) {
		req_data->header.session_id =
			cpu_to_le64(ctx->enc_sess_info.session_id);
		req_data->header.opcode =
			cpu_to_le32(VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	} else {
		req_data->header.session_id =
			cpu_to_le64(ctx->dec_sess_info.session_id);
	    req_data->header.opcode =
			cpu_to_le32(VIRTIO_CRYPTO_CIPHER_DECRYPT);
	}
	req_data->u.sym_req.op_type = cpu_to_le32(VIRTIO_CRYPTO_SYM_OP_CIPHER);
	req_data->u.sym_req.u.cipher.para.iv_len = cpu_to_le32(ivsize);
	req_data->u.sym_req.u.cipher.para.src_data_len =
			cpu_to_le32(req->nbytes);

	dst_len = virtio_crypto_alg_sg_nents_length(req->dst);
	if (unlikely(dst_len > U32_MAX)) {
		pr_err("virtio_crypto: The dst_len is beyond U32_MAX\n");
		err = -EINVAL;
		goto free;
	}

	pr_debug("virtio_crypto: src_len: %u, dst_len: %llu\n",
			req->nbytes, dst_len);

	if (unlikely(req->nbytes + dst_len + ivsize +
		sizeof(vc_req->status) > vcrypto->max_size)) {
		pr_err("virtio_crypto: The length is too big\n");
		err = -EINVAL;
		goto free;
	}

	req_data->u.sym_req.u.cipher.para.dst_data_len =
			cpu_to_le32((uint32_t)dst_len);

	/* Outhdr */
	sg_init_one(&outhdr, req_data, sizeof(*req_data));
	sgs[num_out++] = &outhdr;

	/* IV */
	if (ivsize > 0) { 
		/*
		 * Avoid to do DMA from the stack, switch to using
		 * dynamically-allocated for the IV
		 */
		iv = kzalloc_node(ivsize, GFP_ATOMIC,
					dev_to_node(&vcrypto->vdev->dev));
		if (!iv) {
			err = -ENOMEM;
			goto free;
		}

		memcpy(iv, req->info, ivsize);
		sg_init_one(&iv_sg, iv, ivsize);
		sgs[num_out++] = &iv_sg;
	}
	vc_req->iv = iv;

	/* Source data */
	
	for (i = 0; i < src_nents; i++)
		sgs[num_out++] = &req->src[i];

	/**/

/*
 	for (i = 0; i < num_out; i++) {
        struct scatterlist *sg;
        for (sg = sgs[i]; sg; sg = sg_next(sg))
            total_sg++;
    }
	printk("OUT SG: %u\n", total_sg);
*/
/*
	sg_len = 0;	
	for (i = 0; i < src_nents; i++) {
        for (sg = &req->src[i]; sg; sg = sg_next(sg))
            sg_len ++;
*/
/*
		sg_len = 0;
        for (sg = &req->src[i]; sg; sg = sg_next(sg))
            sg_len += sg->length;
		printk("OUT SG [%d] = %u\n", i, sg_len);
		
		buf = kzalloc_node(sg_len, GFP_ATOMIC,
					dev_to_node(&vcrypto->vdev->dev));
		if (!buf)
			return -ENOMEM;
        
		total_bytes = 0;
		for (sg = &req->src[i]; sg; sg = sg_next(sg)) {
			offset = 0;
			while ((sg_bytes = sg_copy_to_buffer(sg, sg_nents(sg), 
							buf+total_bytes+offset, 
							sg->length-offset)) > 0)
					offset += sg_bytes;
			total_bytes += offset;
		}
		sg_init_one(&out_sg, buf, total_bytes);
		sgs[num_out++] = &out_sg;
		printk("OUT SG [%d] DONE = %u\n", i, total_bytes);
*/
/*
	}
	printk("OUT SG = %d\n", sg_len);
*/
	/**/

	/* Destination data */
	for (i = 0; i < dst_nents; i++)
		sgs[num_out + num_in++] = &req->dst[i];
	
	/* Status */
	sg_init_one(&status_sg, &vc_req->status, sizeof(vc_req->status));
	sgs[num_out + num_in++] = &status_sg;

	vc_req->sgs = sgs;

	spin_lock_irqsave(&data_vq->lock, flags);
	err = virtqueue_add_sgs(data_vq->vq, sgs, num_out,
				num_in, vc_req, GFP_ATOMIC);
	virtqueue_kick(data_vq->vq);
	spin_unlock_irqrestore(&data_vq->lock, flags);
	//ktime_get_ts(&ts1);
	if (unlikely(err < 0))
		goto free_iv;

	return 0;

free_iv:
	if (iv)
		kzfree(iv);
free:
	kzfree(req_data);
	kfree(sgs);
	return err;
}

static int
__virtio_accel_ablkcipher_do_req(struct virtio_crypto_request *vc_req,
		struct ablkcipher_request *req,
		struct data_queue *data_vq,
		__u8 op)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	unsigned int ivsize = crypto_ablkcipher_ivsize(tfm);
	struct virtio_crypto_ablkcipher_ctx *ctx = vc_req->ablkcipher_ctx;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	struct virtio_crypto_op_data_req *req_crypto_head;
	struct virtio_accel_req_head *req_head;
	int src_nents, dst_nents, sg_total;
	int err;
	unsigned long flags;
	struct scatterlist outhdr, iv_sg, status_sg, **sgs, *sg, out_sg;
	int i;
	u64 dst_len;
	unsigned int num_out = 0, num_in = 0, sg_len;
	size_t sg_bytes, offset, total_bytes;
	uint8_t *iv = NULL;
	void *buf = NULL;

	src_nents = sg_nents_for_len(req->src, req->nbytes);
	dst_nents = sg_nents(req->dst);

	pr_debug("virtio_crypto: Number of sgs (src_nents: %d, dst_nents: %d)\n",
			src_nents, dst_nents);

	/* Why 3?  outhdr + iv + inhdr */
	sg_total = src_nents + dst_nents + 3;
	sgs = kzalloc_node(sg_total * sizeof(*sgs), GFP_ATOMIC,
				dev_to_node(&vcrypto->vdev->dev));
	if (!sgs)
		return -ENOMEM;

	req_crypto_head = kzalloc_node(sizeof(*req_crypto_head), GFP_ATOMIC,
				dev_to_node(&vcrypto->vdev->dev));
	if (!req_crypto_head) {
		kfree(sgs);
		return -ENOMEM;
	}

	vc_req->req_data = req_crypto_head;
	vc_req->type = VIRTIO_CRYPTO_SYM_OP_CIPHER;
	/* Head of operation */
	if (op) {
		req_crypto_head->header.session_id =
			cpu_to_le64(ctx->enc_sess_info.session_id);
		req_crypto_head->header.opcode =
			cpu_to_le32(VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	} else {
		req_crypto_head->header.session_id =
			cpu_to_le64(ctx->dec_sess_info.session_id);
	    req_crypto_head->header.opcode =
			cpu_to_le32(VIRTIO_CRYPTO_CIPHER_DECRYPT);
	}
	req_crypto_head->u.sym_req.op_type = cpu_to_le32(VIRTIO_CRYPTO_SYM_OP_CIPHER);
	req_crypto_head->u.sym_req.u.cipher.para.iv_len = cpu_to_le32(ivsize);
	req_crypto_head->u.sym_req.u.cipher.para.src_data_len =
			cpu_to_le32(req->nbytes);

	dst_len = virtio_crypto_alg_sg_nents_length(req->dst);
	if (unlikely(dst_len > U32_MAX)) {
		pr_err("virtio_crypto: The dst_len is beyond U32_MAX\n");
		err = -EINVAL;
		goto free;
	}

	pr_debug("virtio_crypto: src_len: %u, dst_len: %llu\n",
			req->nbytes, dst_len);

	if (unlikely(req->nbytes + dst_len + ivsize +
		sizeof(vc_req->status) > vcrypto->max_size)) {
		pr_err("virtio_crypto: The length is too big\n");
		err = -EINVAL;
		goto free;
	}

	req_crypto_head->u.sym_req.u.cipher.para.dst_data_len =
			cpu_to_le32((uint32_t)dst_len);

	req_head = kzalloc_node(sizeof(*req_head), GFP_ATOMIC,
				dev_to_node(&vcrypto->vdev->dev));
	if (!req_head) {
		err = -ENOMEM;
		goto free;
	}
	req_head->opcode = cpu_to_le32(VIRTIO_ACCEL_CRYPTO);
	req_head->crypto_head = *req_crypto_head;

	/* Outhdr */
	sg_init_one(&outhdr, req_head, sizeof(*req_head));
	sgs[num_out++] = &outhdr;

	/* IV */
	if (ivsize > 0) { 
		/*
		 * Avoid to do DMA from the stack, switch to using
		 * dynamically-allocated for the IV
		 */
		iv = kzalloc_node(ivsize, GFP_ATOMIC,
					dev_to_node(&vcrypto->vdev->dev));
		if (!iv) {
			err = -ENOMEM;
			goto free;
		}

		memcpy(iv, req->info, ivsize);
		sg_init_one(&iv_sg, iv, ivsize);
		sgs[num_out++] = &iv_sg;
	}
	vc_req->iv = iv;

	/* Source data */	
	for (i = 0; i < src_nents; i++)
		sgs[num_out++] = &req->src[i];

	/* Destination data */
	for (i = 0; i < dst_nents; i++)
		sgs[num_out + num_in++] = &req->dst[i];
	
	/* Status */
	sg_init_one(&status_sg, &vc_req->status, sizeof(vc_req->status));
	sgs[num_out + num_in++] = &status_sg;

	vc_req->sgs = sgs;

	spin_lock_irqsave(&data_vq->lock, flags);
	err = virtqueue_add_sgs(data_vq->vq, sgs, num_out,
				num_in, vc_req, GFP_ATOMIC);
	virtqueue_kick(data_vq->vq);
	spin_unlock_irqrestore(&data_vq->lock, flags);
	//ktime_get_ts(&ts1);
	if (unlikely(err < 0))
		goto free_iv;

	return 0;

free_iv:
	if (iv)
		kzfree(iv);
free:
	kzfree(req_crypto_head);
	kfree(sgs);
	return err;
}

static int virtio_crypto_ablkcipher_encrypt(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *atfm = crypto_ablkcipher_reqtfm(req);
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_ablkcipher_ctx(atfm);
	struct virtio_crypto_request *vc_req = ablkcipher_request_ctx(req);
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int ret;
	/* Use the first data virtqueue as default */
	struct data_queue *data_vq = &vcrypto->data_vq[0];;
	/*
	mutex_lock(&algs_lock);
	//printk("vcrypto->curr_queue: %d\n", vcrypto->curr_queue);
	//printk("vcrypto->max_data_queues: %d\n", vcrypto->max_data_queues);
	data_vq = &vcrypto->data_vq[vcrypto->curr_queue++ - 1];
	if (vcrypto->curr_queue > vcrypto->max_data_queues)
		vcrypto->curr_queue = 1;
	mutex_unlock(&algs_lock);
	*/
//	struct timespec ts1, ts2, ts;
	
	vc_req->ablkcipher_ctx = ctx;
	vc_req->ablkcipher_req = req;
//	ktime_get_ts(&ts1);
	ret = __virtio_accel_ablkcipher_do_req(vc_req, req, data_vq, 1);
	
	if (ret < 0) {
		pr_err("virtio_crypto: Encryption failed!\n");
		return ret;
	}
//	ktime_get_ts(&ts2);
//	ts = timespec_sub(ts2, ts1);
//	printk("TIME SEND: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);
//	printk("VIRTQUEUE FREE: %u \r\n", data_vq->vq->num_free);

	return -EINPROGRESS;
}

static int virtio_crypto_ablkcipher_decrypt(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *atfm = crypto_ablkcipher_reqtfm(req);
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_ablkcipher_ctx(atfm);
	struct virtio_crypto_request *vc_req = ablkcipher_request_ctx(req);
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int ret;
	/* Use the first data virtqueue as default */
	struct data_queue *data_vq = &vcrypto->data_vq[0];

	vc_req->ablkcipher_ctx = ctx;
	vc_req->ablkcipher_req = req;

	ret = __virtio_crypto_ablkcipher_do_req(vc_req, req, data_vq, 0);
	if (ret < 0) {
		pr_err("virtio_crypto: Decryption failed!\n");
		return ret;
	}

	return -EINPROGRESS;
}

static int virtio_crypto_ablkcipher_init(struct crypto_tfm *tfm)
{
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_tfm_ctx(tfm);

	tfm->crt_ablkcipher.reqsize = sizeof(struct virtio_crypto_request);
	ctx->tfm = tfm;

	return 0;
}

static void virtio_crypto_ablkcipher_exit(struct crypto_tfm *tfm)
{
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_tfm_ctx(tfm);

	if (!ctx->vcrypto)
		return;

	virtio_crypto_alg_ablkcipher_close_session(ctx, 1);
	virtio_crypto_alg_ablkcipher_close_session(ctx, 0);
	virtcrypto_dev_put(ctx->vcrypto);
	ctx->vcrypto = NULL;
}

static struct crypto_alg virtio_crypto_algs[] = { {
	.cra_name = "ecb(aes)",
	.cra_driver_name = "virtio_crypto_aes_ecb",
/*
	.cra_name = "cbc(aes)",
	.cra_driver_name = "virtio_crypto_aes_cbc",
*/
	.cra_priority = 501,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize  = sizeof(struct virtio_crypto_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_module = THIS_MODULE,
	.cra_type = &crypto_ablkcipher_type,
	.cra_init = virtio_crypto_ablkcipher_init,
	.cra_exit = virtio_crypto_ablkcipher_exit,
	.cra_u = {
	   .ablkcipher = {
			.setkey = virtio_crypto_ablkcipher_setkey,
			.decrypt = virtio_crypto_ablkcipher_decrypt,
			.encrypt = virtio_crypto_ablkcipher_encrypt,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
	/*		.ivsize = AES_BLOCK_SIZE,*/
		},
	},
} };

int virtio_crypto_algs_register(void)
{
	int ret = 0;

	mutex_lock(&algs_lock);
	if (++virtio_crypto_active_devs != 1)
		goto unlock;

	ret = crypto_register_algs(virtio_crypto_algs,
			ARRAY_SIZE(virtio_crypto_algs));
	if (ret)
		virtio_crypto_active_devs--;

unlock:
	mutex_unlock(&algs_lock);
	return ret;
}

void virtio_crypto_algs_unregister(void)
{
	mutex_lock(&algs_lock);
	if (--virtio_crypto_active_devs != 0)
		goto unlock;

	crypto_unregister_algs(virtio_crypto_algs,
			ARRAY_SIZE(virtio_crypto_algs));

unlock:
	mutex_unlock(&algs_lock);
}






int virtio_accel_req_create_session(virtio_accel_request *req, 
									virtio_accel *va, accel_session *sess)
{
	struct scatterlist hdr_sg, key_sg, status_sg, **sgs;
	struct virtio_accel_header *h = &req->header;

	// TODO: check op
	h->op = cpu_to_le32(sess->op);

	h->u.crypto_op.key = kzalloc_node(sizeof(*h->u.crypto_op.key), GFP_ATOMIC,
								dev_to_node(&vcrypto->vdev->dev));
	if (!h->crypto_op.key)
		return -ENOMEM;
	
	if (unlikely(copy_from_user(&h->u.crypto_op.key, sess->u.crypto_op.key, 
								sizeof(sess))))
		ret = -EFAULT;
		goto free;
	}

	sgs = kzalloc_node(3 * sizeof(*sgs), GFP_ATOMIC,
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
	sg_init_one(&status_sg, &req->status, sizeof(req->status));
	sgs[2] = &status_sg;

	req->vaccel = vaccel;
	req->sgs = sgs;
	req->out_sgs = 2;
	req->in_sgs = 1;

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
