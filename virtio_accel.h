#ifndef _VIRTIO_ACCEL_H
#define _VIRTIO_ACCEL_H

struct sessions_list {
	struct list_head list;
	u32 id;
}

struct virtio_accel_crypto_op {
	__le32 cipher;
	__le32 keylen;
	__le32 *key;
	__u32 padding;
}

struct virtio_accel_header {
	__le32 session_id;
	__le32 op;
	/* session create structs */
	union {
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
	struct virtio_accel_header header;
	struct virtio_accel *vaccel;
	struct scatterlist **sgs;
	unsigned int out_sgs;
	unsigned int in_sgs;
	u32 status;
}

struct virtio_accel_file {
	struct virtio_accel *vaccel;
	struct list_head sessions;
}


int virtio_accel_req_create_session(virtio_accel_request *req, virtio_accel *va, accel_session *sess);
int virtio_accel_do_req(virtio_accel_request *req);

#endif /* _VIRTIO_ACCEL_H */
