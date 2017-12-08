#ifndef _VIRTIO_ACCEL_H
#define _VIRTIO_ACCEL_H

#include <linux/completion.h>

struct sessions_list {
	struct list_head list;
	u32 id;
}

struct virtio_accel_crypto_sess {
	__virtio32 cipher;
	__virtio32 keylen;
	__u8 *key;
	__u8 padding[7];
}

struct virtio_accel_crypto_op {
	__virtio32 src_len;
	__virtio32 dst_len;
	__virtio32 iv_len;
	__u8 *src;
	__u8 *dst;
	__u8 *iv;
	__u8 padding;
}

struct virtio_accel_hdr {
	__virtio32 session_id;
	__virtio32 op;
	/* session create structs */
	union {
		struct virtio_accel_crypto_sess crypto_sess;
		struct virtio_accel_crypto_op crypto_op;
	} u;
}

struct virtio_accel {
	struct virtio_device *vdev;

	struct virtqueue *vq;
	spinlock_t vq_lock;

	unsigned int dev_minor;
	
	unsigned long status;
	struct module *owner;
};

struct virtio_accel_request {
	struct virtio_accel_hdr hdr;
	struct virtio_accel *vaccel;
	struct scatterlist **sgs;
	unsigned int out_sgs;
	unsigned int in_sgs;
	void *priv;
	u32 status;
	struct completion completion;
}

struct virtio_accel_file {
	struct virtio_accel *vaccel;
	struct list_head sessions;
}


int virtaccel_req_create_session(virtio_accel_request *req);
int virtaccel_req_destroy_session(virtio_accel_request *req);
int virtaccel_req_crypto_operation(virtio_accel_request *req);
int virtaccel_do_req(virtio_accel_request *req);

#define virtaccel_req_crypto_encrypt(a) \
	virtaccel_req_crypto_operation(a, VIRTIO_ACCEL_CRYPTO_CIPHER_ENCRYPT)

#define virtaccel_req_crypto_decrypt(a) \
	virtaccel_req_crypto_operation(a, VIRTIO_ACCEL_CRYPTO_CIPHER_DECRYPT)

#endif /* _VIRTIO_ACCEL_H */
