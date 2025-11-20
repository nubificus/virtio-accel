// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <linux/hashtable.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/stddef.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

#include "profiler.h"
#include "buffer.h"
#include "common.h"
#include "session.h"
#include <linux/virtio_accel.h>

static bool profiling = true;
module_param(profiling, bool, S_IRUGO);
MODULE_PARM_DESC(profiling, "virtio-accel profiling");

static int timer_sample_add(struct virtio_accel_timer *timer)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL;

	if (!timer)
		return 0;

	sample = kzalloc(sizeof(*sample), GFP_KERNEL);
	if (!sample)
		return 0;

	sample->start = ktime_get();
	list_add_tail(&sample->node, &timer->samples);
	return 1;
#endif
	return 0;
}

static int timer_sample_time(struct virtio_accel_timer *timer)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL;

	if (timer) {
		// FIXME: list empty
		sample =
			list_last_entry(&timer->samples, typeof(*sample), node);

		// FIXME: time not 0
		sample->time = ktime_sub(ktime_get(), sample->start);
		return 1;
	}
#endif
	return 0;
}

static struct virtio_accel_timer *
timer_get_by_name(struct virtio_accel_session *sess, const char *name)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL, *t;
	int bkt;

	hash_for_each(sess->timers, bkt, t, node)
	{
		if (strncmp(t->name, name, VIRTIO_ACCEL_TIMERS_NAME_MAX) == 0) {
			timer = t;
			break;
		}
	}

	return timer;
#else
	return NULL;
#endif
}

static struct virtio_accel_timer *
timer_create_and_add(struct virtio_accel_session *sess, const char *name)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = kzalloc(sizeof(*timer), GFP_KERNEL);
	if (timer) {
		strncpy(timer->name, name, VIRTIO_ACCEL_TIMERS_NAME_MAX);
		INIT_LIST_HEAD(&timer->samples);
		hash_add(sess->timers, &timer->node,
			 (unsigned long)timer->name);
		sess->nr_timers++;
	}

	return timer;
#else
	return NULL;
#endif
}

int virtio_accel_profiler_timer_start(struct virtio_accel_session *sess,
				      char *name)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;

	if (!profiling || !name || !sess || !sess->id)
		return 0;

	timer = timer_get_by_name(sess, name);
	if (timer == NULL) {
		timer = timer_create_and_add(sess, name);
		if (!timer)
			return -ENOMEM;
		timer->nr_samples = 0;
	}

	timer->nr_samples += timer_sample_add(timer);
#endif
	return 0;
}

void virtio_accel_profiler_timer_stop(struct virtio_accel_session *sess,
				      char *name)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;

	if (!profiling || !name || !sess || !sess->id)
		return;

	timer = timer_get_by_name(sess, name);
	if (!timer)
		return;

	timer_sample_time(timer);
#endif
}

void virtio_accel_profiler_timer_del(struct virtio_accel_timer *timer)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL, *tmp;

	if (!profiling)
		return;

	if (!timer)
		return;

	list_for_each_entry_safe(sample, tmp, &timer->samples, node)
	{
		list_del(&sample->node);
		kfree(sample);
	}

	hash_del(&timer->node);
	kfree(timer);
#endif
}

void virtio_accel_profiler_timers_del_by_name(struct virtio_accel_session *sess,
					      char *name)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;

	if (!profiling)
		return;

	if (!sess)
		return;

	timer = timer_get_by_name(sess, name);
	if (!timer)
		return;

	virtio_accel_profiler_timer_del(timer);
	sess->nr_timers--;
#endif
}

void virtio_accel_profiler_timers_del_all(struct virtio_accel_session *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	struct hlist_node *tmp;
	int bkt;

	if (!profiling)
		return;

	if (!sess)
		return;

	hash_for_each_safe(sess->timers, bkt, tmp, timer, node)
	{
		virtio_accel_profiler_timer_del(timer);
	}
	sess->nr_timers = 0;
#endif
}

#define FORMAT_STRING \
	"[virtio-accel] %s: total_time: %lld nsec nr_entries: %d\n"

static s64 timer_sample_get_last(struct virtio_accel_timer *timer)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL;
	// FIXME: list empty
	sample = list_last_entry(&timer->samples, typeof(*sample), node);

	return ktime_to_ns(sample->time);
#else
	return 0;
#endif
}

static s64 timer_sample_get_total(struct virtio_accel_timer *timer)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL, *tmp;
	s64 total = 0;

	list_for_each_entry_safe(sample, tmp, &timer->samples, node)
	{
		total += ktime_to_ns(sample->time);
	}

	return total;
#else
	return 0;
#endif
}

void virtio_accel_profiler_timers_print_by_name(
	struct virtio_accel_session *sess, char *name)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = timer_get_by_name(sess, name);
	s64 time;

	if (!profiling)
		return;

	if (timer == NULL)
		return;

	time = timer_sample_get_last(timer);
	vacl_info(FORMAT_STRING, timer->name, time, 1);
#endif
}

void virtio_accel_profiler_timers_print_all(struct virtio_accel_session *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt;

	if (!profiling)
		return;

	if (!sess)
		return;

	hash_for_each(sess->timers, bkt, timer, node)
	{
		s64 time = timer_sample_get_last(timer);
		vacl_info(FORMAT_STRING, timer->name, time, 1);
	}
#endif
}

void virtio_accel_profiler_timers_print_all_total(
	struct virtio_accel_session *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt;

	if (!profiling)
		return;

	if (!sess)
		return;

	hash_for_each(sess->timers, bkt, timer, node)
	{
		s64 time = timer_sample_get_total(timer);
		vacl_info(FORMAT_STRING, timer->name, time, 1);
	}
#endif
}

static unsigned int
get_region_samples(struct virtio_accel_timer *timer,
		   struct virtio_accel_profiler_sample *samples,
		   unsigned int nr_samples)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL, *tmp;
	unsigned int i = 0;

	list_for_each_entry_safe(sample, tmp, &timer->samples, node)
	{
		if (i == nr_samples) {
			vacl_warn(
				"Not all samples for %s can be returned (allocated: %u vs total: %u)",
				timer->name, nr_samples, timer->nr_samples);
			break;
		}

		samples[i].start = ktime_to_ns(sample->start);
		samples[i].time = ktime_to_ns(sample->time);
		i++;
	}

	return i;
#else
	return 0;
#endif
}

#define TIMERS_NAME_PREFIX "[virtio-accel]"
unsigned int
virtio_accel_profiler_get_regions(struct virtio_accel_session *sess,
				  struct virtio_accel_profiler_region *regions,
				  struct virtio_accel_buffer *samples_bufs,
				  unsigned int nr_regions)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt;
	unsigned int i = 0;

	if (!profiling)
		return 0;

	if (!nr_regions)
		return 0;

	hash_for_each(sess->timers, bkt, timer, node)
	{
		if (i == nr_regions) {
			vacl_warn(
				"Not all timers can be returned (allocated: %u vs total: %u)",
				nr_regions, sess->nr_timers);
			break;
		}

		snprintf(regions[i].name, VIRTIO_ACCEL_TIMERS_NAME_MAX, "%s %s",
			 TIMERS_NAME_PREFIX, timer->name);

		struct virtio_accel_profiler_sample *samples =
			(struct virtio_accel_profiler_sample *)
				virtio_accel_buffer_get_mapped(
					&samples_bufs[i]);
		if (!samples)
			break;

		regions[i].nr_samples = get_region_samples(
			timer, samples, regions[i].max_samples);
		i++;
	}

	return i;
#else
	return 0;
#endif
}
