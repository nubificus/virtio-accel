// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_REQUEST_H
#define _VIRTIO_ACCEL_REQUEST_H

#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#include "core.h"
#include <linux/virtio_accel.h>

struct virtio_accel_sg_allocs {
	struct scatterlist **allocs;
	unsigned int count;
	unsigned int capacity;
};

struct virtio_accel_request {
	struct virtio_accel *vacl;

	unsigned int cmd;
	struct virtio_accel_header hdr;
	union {
		struct {
			struct virtio_accel_arg_header *out;
			struct virtio_accel_arg_header *in;
		} arg_hdrs;

		struct {
			struct virtio_accel_profiler_region_hdr *regions;
			struct virtio_accel_profiler_sample_hdr *samples;
		} timer_hdrs;
	};

	struct scatterlist **sgs;
	unsigned int nr_out_sgs;
	unsigned int nr_in_sgs;
	struct virtio_accel_sg_allocs sg_allocs;

	struct virtio_accel_request *parent;
	atomic_t chunk_count;

	struct virtio_accel_op_request *op_req;
	struct completion completion;

	u8 status;
	int ret;
};

struct virtio_accel_request *
virtio_accel_request_new(struct virtio_accel *vacl, u32 cmd,
			 struct virtio_accel_op_request *op_req);
struct virtio_accel_request *
virtio_accel_request_new_with_parent(struct virtio_accel_request *parent);
void virtio_accel_request_delete(struct virtio_accel_request *req);
int virtio_accel_request_submit(struct virtio_accel_request *req);
void virtio_accel_request_handle_result(struct virtio_accel_request *req);
int virtio_accel_request_commit(struct virtio_accel_request *req);

#endif /* _VIRTIO_ACCEL_REQUEST_H */
