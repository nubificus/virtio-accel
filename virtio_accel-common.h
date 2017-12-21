#ifndef _VIRTIO_ACCEL_COMMON_H
#define _VIRTIO_ACCEL_COMMON_H

#include "virtio_accel.h"
#include <linux/completion.h>

#define VQ_NAME_LEN 16

struct sessions_list {
	struct list_head list;
	u32 id;
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
	struct completion completion;
	u32 status;
	int ret;
};

struct virtio_accel_file {
	struct virtio_accel *vaccel;
	struct list_head sessions;
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
#define virtaccel_req_crypto_encrypt(a) \
	virtaccel_req_crypto_operation(a, VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT)
#define virtaccel_req_crypto_decrypt(a) \
	virtaccel_req_crypto_operation(a, VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT)

int virtaccel_req_gen_create_session(struct virtio_accel_req *req);
int virtaccel_req_gen_destroy_session(struct virtio_accel_req *req);
int virtaccel_req_gen_operation(struct virtio_accel_req *req);
void virtaccel_clear_req(struct virtio_accel_req *req);
void virtaccel_handle_req_result(struct virtio_accel_req *req);
int virtaccel_do_req(struct virtio_accel_req *req);

#endif /* _VIRTIO_ACCEL_COMMON_H */
