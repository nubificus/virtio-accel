#ifndef _VIRTIO_ACCEL_H
#define _VIRTIO_ACCEL_H

#include <linux/virtio_types.h>
#include <linux/completion.h>

#define VIRTIO_ID_ACCEL 21

#define VQ_NAME_LEN 16

#define VIRTIO_ACCEL_S_HW_READY  (1 << 0)

/* status */
#define VIRTIO_ACCEL_OK        0
#define VIRTIO_ACCEL_ERR       1
#define VIRTIO_ACCEL_BADMSG    2
#define VIRTIO_ACCEL_NOTSUPP   3
#define VIRTIO_ACCEL_INVSESS   4 /* Invalid session id */

struct sessions_list {
	struct list_head list;
	u32 id;
};

struct virtio_accel_crypto_sess {
#define VIRTIO_ACCEL_C_NO_CIPHER      0
#define VIRTIO_ACCEL_C_CIPHER_AES_ECB 1
#define VIRTIO_ACCEL_C_CIPHER_AES_CBC 2
#define VIRTIO_ACCEL_C_CIPHER_AES_CTR 3
#define VIRTIO_ACCEL_C_CIPHER_AES_XTS 4
	__virtio32 cipher;
	__virtio32 keylen;
	__u8 *key;
	__u8 padding[7];
};

struct virtio_accel_crypto_op {
	__virtio32 src_len;
	__virtio32 dst_len;
	__virtio32 iv_len;
	__u8 *src;
	__u8 *dst;
	__u8 *iv;
	__u8 padding;
};

struct virtio_accel_hdr {
	__virtio32 session_id;

#define VIRTIO_ACCEL_NO_OP                       0
#define VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION  1
#define VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION 2
#define VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT         3
#define VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT         4
	__virtio32 op;
	/* session create structs */
	union {
		struct virtio_accel_crypto_sess crypto_sess;
		struct virtio_accel_crypto_op crypto_op;
	} u;
};


struct virtio_accel_vq {
    struct virtqueue *vq;
    spinlock_t lock;
    char name[VQ_NAME_LEN];
};

struct virtio_accel {
	struct virtio_device *vdev;
	struct virtio_accel_vq *vq;
	unsigned int dev_minor;
	unsigned long status;

	struct module *owner;
	struct list_head list;
	atomic_t ref_count;
	uint8_t dev_id;
};

struct virtio_accel_req {
	struct virtio_accel_hdr hdr;
	struct virtio_accel *vaccel;
	struct scatterlist **sgs;
	unsigned int out_sgs;
	unsigned int in_sgs;
	void *priv;
	void __user *usr;
	u32 status;
	struct completion completion;
};

struct virtio_accel_file {
	struct virtio_accel *vaccel;
	struct list_head sessions;
};


struct virtio_accel_crypto_conf {
    /* Maximum length of cipher key */
    __u32 max_cipher_key_len;
    /* Maximum length of authenticated key */
    __u32 max_auth_key_len;
};

struct virtio_accel_conf {
	__u32 status;
    /* Supported service mask */
    __u32 services;
    /* Maximum size of each crypto request's content */
    __u64 max_size;

    union {
        struct virtio_accel_crypto_conf crypto;
    } u;
};


/* virtio_accel-mgr */
int virtaccel_devmgr_add_dev(struct virtio_accel *vaccel);
struct list_head *virtaccel_devmgr_get_head(void);
void virtaccel_devmgr_rm_dev(struct virtio_accel *vaccel);
struct virtio_accel *virtaccel_devmgr_get_first(void);
int virtaccel_dev_in_use(struct virtio_accel *vaccel);
int virtaccel_dev_get(struct virtio_accel *vaccel);
void virtaccel_dev_put(struct virtio_accel *vaccel);
int virtaccel_dev_started(struct virtio_accel *vaccel);
struct virtio_accel *virtaccel_get_dev_node(int node);
int virtaccel_dev_start(struct virtio_accel *vcrypto);
void virtaccel_dev_stop(struct virtio_accel *vcrypto);

/* virtio_accel-reqs */
int virtaccel_req_crypto_create_session(struct virtio_accel_req *req);
int virtaccel_req_crypto_destroy_session(struct virtio_accel_req *req);
int virtaccel_req_crypto_operation(struct virtio_accel_req *req, int opcode);
void virtaccel_clear_req(struct virtio_accel_req *req);
void virtaccel_handle_req_result(struct virtio_accel_req *req);
int virtaccel_do_req(struct virtio_accel_req *req);

#define virtaccel_req_crypto_encrypt(a) \
	virtaccel_req_crypto_operation(a, VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT)

#define virtaccel_req_crypto_decrypt(a) \
	virtaccel_req_crypto_operation(a, VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT)

#endif /* _VIRTIO_ACCEL_H */
