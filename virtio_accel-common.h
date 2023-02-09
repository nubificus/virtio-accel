#ifndef _VIRTIO_ACCEL_COMMON_H
#define _VIRTIO_ACCEL_COMMON_H

#include <linux/completion.h>
#include <linux/types.h>
#include <linux/scatterlist.h>
#include "virtio_accel.h"
#include "accel.h"

#ifndef fallthrough
# if __has_attribute(__fallthrough__)
#  define fallthrough                    __attribute__((__fallthrough__))
# else
#  define fallthrough                    do {} while (0)  /* fallthrough */
# endif
#endif

#define PAGEOFFSET(buf) ((unsigned long)buf & ~PAGE_MASK)
#define VQ_NAME_LEN 16

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
int virtaccel_req_create_session(struct virtio_accel_req *req);
int virtaccel_req_destroy_session(struct virtio_accel_req *req);
int virtaccel_req_operation(struct virtio_accel_req *req);
int virtaccel_req_timers(struct virtio_accel_req *req);
void virtaccel_clear_req(struct virtio_accel_req *req);
void virtaccel_handle_req_result(struct virtio_accel_req *req);
int virtaccel_do_req(struct virtio_accel_req *req);

/* virtio_accel-zc */
int virtaccel_map_user_buf(struct sg_table **m_sgt, struct page ***m_pages,
		void __user *_uaddr, size_t ulen,
		int write, struct virtio_device *vdev);

void virtaccel_unmap_user_buf(struct sg_table *m_sgt, struct page **m_pages,
		const unsigned int nr_pages);

/* virtio_accel-session */
struct virtio_accel_sess *virtaccel_session_create_and_add(
		struct accel_session *accel_sess, struct virtio_accel_req *req);
void virtaccel_session_delete(struct accel_session *accel_sess,
		struct virtio_accel_req *req);
struct virtio_accel_sess *virtaccel_session_get_by_id(u32 id,
		struct virtio_accel_req *req);

#endif /* _VIRTIO_ACCEL_COMMON_H */
