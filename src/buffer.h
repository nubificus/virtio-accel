// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_BUFFER_H
#define _VIRTIO_ACCEL_BUFFER_H

#include <linux/compiler_types.h>
#include <linux/mm_types.h>
#include <linux/types.h>

struct virtio_accel_buffer {
	union {
		struct {
			struct sg_table *sgt;
			struct page **pages;
			unsigned int nr_pages;
			unsigned int offset;
			void *v_addr;
		};
		void *buf;
	};
	void __user *u_buf;
	unsigned int len;
	bool pinned;
};

int virtio_accel_buffer_init(struct virtio_accel_buffer *v_buf,
			     void __user *u_buf, size_t u_len, bool write);
void virtio_accel_buffer_release(struct virtio_accel_buffer *v_buf, bool write);

void *virtio_accel_buffer_map(struct virtio_accel_buffer *v_buf);
void virtio_accel_buffer_unmap(struct virtio_accel_buffer *v_buf);
int virtio_accel_buffer_copy_to_user(struct virtio_accel_buffer *v_buf);

#endif /* _VIRTIO_ACCEL_BUFFER_H */
