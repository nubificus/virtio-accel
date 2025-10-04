// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_COMMON_H
#define _VIRTIO_ACCEL_COMMON_H

#include "virtio_accel.h"
#include "accel.h"
#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/version.h>

#ifndef fallthrough
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough \
	do {        \
	} while (0) /* fallthrough */
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define kfree_sensitive kzfree;
#endif

#define VQ_NAME_LEN 16

#define VIRTQUEUE_MAX_SIZE 1024
#define MAX_SGS_PER_CHUNK 512

struct virtio_accel_sess {
	u32 id;

#define TIMERS_BUCKET_CNT (1u << 4) // 16
	struct hlist_head timers[TIMERS_BUCKET_CNT];

	unsigned int nr_timers;
	struct list_head node;
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
	struct list_head sessions;
	atomic64_t next_request_id;
};

struct virtio_accel_arg {
	struct virtio_accel_arg_hdr hdr;
	void *buf;
	void __user *usr_buf;
	struct page **usr_pages;
	unsigned int usr_npages;
};

struct virtio_accel_sg_allocs {
	struct scatterlist **chains;
	unsigned int count;
};

struct virtio_accel_req {
	struct virtio_accel *vaccel;

	struct virtio_accel_hdr hdr;
	struct virtio_accel_arg_hdr *out_arg_hdrs;
	struct virtio_accel_arg_hdr *in_arg_hdrs;

	struct scatterlist **sgs;
	unsigned int out_sgs;
	unsigned int in_sgs;

	struct virtio_accel_req *parent;
	atomic_t chunk_count;
	struct virtio_accel_sg_allocs chunk_allocs;

	void *priv;
	void __user *usr;
	struct completion completion;

	u8 status;
	int ret;
};

struct virtio_accel_file {
	struct virtio_accel *vaccel;
};

#define virtaccel_err(fmt, ...) pr_err("virtio-accel: " fmt, ##__VA_ARGS__)
#define virtaccel_warn(fmt, ...) pr_warn("virtio-accel: " fmt, ##__VA_ARGS__)
#define virtaccel_info(fmt, ...) pr_info("virtio-accel: " fmt, ##__VA_ARGS__)
#define virtaccel_debug(fmt, ...) pr_debug("virtio-accel: " fmt, ##__VA_ARGS__)

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
int virtaccel_dev_start(struct virtio_accel *vaccel);
void virtaccel_dev_stop(struct virtio_accel *vaccel);

/* virtio_accel-reqs */
struct virtio_accel_req *virtaccel_req_new(struct virtio_accel *vaccel,
					   void __user *usr);
struct virtio_accel_req *
virtaccel_req_new_with_parent(struct virtio_accel_req *parent);
void virtaccel_req_clear(struct virtio_accel_req *req);
void virtaccel_req_delete(struct virtio_accel_req *req);
int virtaccel_req_operation(struct virtio_accel_req *req, u32 cmd);
void virtaccel_req_handle_result(struct virtio_accel_req *req);
int virtaccel_req_submit(struct virtio_accel_req *req);

/* virtio_accel-zc */
int virtaccel_map_user_buf(struct sg_table **m_sgt, struct page ***m_pages,
			   void __user *_uaddr, size_t ulen, int write,
			   struct virtio_device *vdev);

void virtaccel_unmap_user_buf(struct sg_table *m_sgt, struct page **m_pages,
			      unsigned int nr_pages);

/* virtio_accel-session */
struct virtio_accel_sess *
virtaccel_session_create_and_add(u64 id, struct virtio_accel_req *req);
void virtaccel_session_delete(u64 id, struct virtio_accel_req *req);
struct virtio_accel_sess *
virtaccel_session_get_by_id(u64 id, struct virtio_accel_req *req);

#endif /* _VIRTIO_ACCEL_COMMON_H */
