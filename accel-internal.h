// SPDX-License-Identifier: GPL-2.0

#ifndef _ACCEL_INTERNAL_H
#define _ACCEL_INTERNAL_H

#include "accel.h"

struct accel_buf {
	union {
		struct {
			struct sg_table *sgt;
			struct page **pages;
			unsigned int offset;
			void *v_addr;
		};
		void *buf;
	};
	void __user *u_buf;
	unsigned int len;
	bool pinned;
};

struct accel_op_req {
	struct accel_op u_op;
	struct accel_arg *out;
	struct accel_arg *in;
	struct accel_buf *out_bufs;
	struct accel_buf *in_bufs;
};

int accel_buf_init(struct accel_buf *a_buf, void __user *u_buf, size_t u_len,
		   bool write);
void accel_buf_release(struct accel_buf *a_buf, bool write);

void *accel_buf_map(struct accel_buf *a_buf);
void accel_buf_unmap(struct accel_buf *a_buf);
int accel_buf_copy_to_user(struct accel_buf *a_buf);

#endif /* _ACCEL_INTERNAL_H */
