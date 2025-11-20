// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_PROFILER_H
#define _VIRTIO_ACCEL_PROFILER_H

#include <linux/hashtable.h>
#include <linux/ktime.h>
#include <linux/types.h>

#include "buffer.h"
#include "session.h"
#include <linux/virtio_accel.h>

#define VIRTIO_ACCEL_TIMERS_SAMPLE_BUCKET_CNT (1u << 4) // 16

struct virtio_accel_timer_sample {
	ktime_t start;
	ktime_t time;
	struct list_head node;
};

struct virtio_accel_timer {
	char name[VIRTIO_ACCEL_TIMERS_NAME_MAX];
	unsigned int nr_samples;
	struct list_head samples;
	struct hlist_node node;
};

#ifdef PROFILING
#define virtio_accel_profiler_timers_init(sess) hash_init((sess)->timers);
#define virtio_accel_profiler_timers_free(sess) \
	virtio_accel_profiler_timers_del_all(sess);
#else
#define virtio_accel_profiler_timers_init(sess)
#define virtio_accel_profiler_timers_free(sess)
#endif

int virtio_accel_profiler_timer_start(struct virtio_accel_session *sess,
				      char *name);
void virtio_accel_profiler_timer_stop(struct virtio_accel_session *sess,
				      char *name);
void virtio_accel_profiler_timer_del(struct virtio_accel_timer *timer);
void virtio_accel_profiler_timers_del_by_name(struct virtio_accel_session *sess,
					      char *name);
void virtio_accel_profiler_timers_del_all(struct virtio_accel_session *sess);
void virtio_accel_profiler_timers_print_by_name(
	struct virtio_accel_session *sess, char *name);
void virtio_accel_profiler_timers_print_all(struct virtio_accel_session *sess);
void virtio_accel_profiler_timers_print_all_total(
	struct virtio_accel_session *sess);
unsigned int
virtio_accel_profiler_get_regions(struct virtio_accel_session *sess,
				  struct virtio_accel_profiler_region *regions,
				  struct virtio_accel_buffer *samples_bufs,
				  unsigned int nr_regions);

#endif /* _VIRTIO_ACCEL_PROFILER_H */
