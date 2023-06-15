#ifndef _VIRTIO_ACCEL_PROF_H
#define _VIRTIO_ACCEL_PROF_H

#include <linux/timekeeping.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include "virtio_accel-common.h"
#include "accel.h"

#define TIMERS_SAMPLE_BUCKET_CNT (1u << 4) // 16


struct virtio_accel_timer_sample {
	ktime_t start;
	ktime_t time;
	struct list_head node;
};

struct virtio_accel_timer {
	char name[TIMERS_NAME_MAX];
	unsigned int nr_samples;
	struct list_head samples;
	struct hlist_node node;
};

#ifdef PROFILING
#define virtaccel_timers_init(vaccel) hash_init(vaccel->timers);
#define virtaccel_timers_free(vaccel) virtaccel_timers_del_all(vaccel);
#else
#define virtaccel_timers_init(vaccel)
#define virtaccel_timers_free(vaccel)
#endif

int virtaccel_timer_start(char *name, struct virtio_accel_sess *sess);

void virtaccel_timer_stop(char *name, struct virtio_accel_sess *sess);

void virtaccel_timer_del(struct virtio_accel_timer *timer);

void virtaccel_timers_del_by_name(char *name, struct virtio_accel_sess *sess);

void virtaccel_timers_del_all(struct virtio_accel_sess *sess);

void virtaccel_timers_print_by_name(char *name, struct virtio_accel_sess *sess);

void virtaccel_timers_print_all(struct virtio_accel_sess *sess);

void virtaccel_timers_print_all_total(struct virtio_accel_sess *sess);

int virtaccel_timers_print_by_name_to_buf(char **buf,
		char *name, struct virtio_accel_sess *sess);

int virtaccel_timers_print_all_to_buf(char **buf,
		struct virtio_accel_sess *sess);

int virtaccel_timers_print_all_total_to_buf(struct accel_arg *tbuf,
		struct virtio_accel_sess *sess);

int virtaccel_timers_virtio_to_accel(struct accel_prof_region *accel_timers,
		int nr_accel_timers, struct virtio_accel_sess *sess);

#endif /* _VIRTIO_ACCEL_PROF_H */
