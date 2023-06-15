#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

#include "virtio_accel-prof.h"
#include "accel.h"

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
		sample = list_last_entry(&timer->samples, typeof(*sample), node);

		// FIXME: time not 0
		sample->time = ktime_sub(ktime_get(), sample->start);
		return 1;
	}
#endif
	return 0;
}

static struct virtio_accel_timer *timer_get_by_name(const char *name,
		struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL, *t;
	int bkt;

	hash_for_each(sess->timers, bkt, t, node) {
		if (strncmp(t->name, name, TIMERS_NAME_MAX) == 0) {
			timer = t;
			break;
		}
	}

	return timer;
#else
	return NULL;
#endif
}

static struct virtio_accel_timer *timer_create_and_add(const char *name,
		struct virtio_accel_sess *sess)
{
#ifdef PROFILING
		struct virtio_accel_timer *timer = kzalloc(sizeof(*timer), GFP_KERNEL);
		if (timer) {
			strncpy(timer->name, name, TIMERS_NAME_MAX);
			INIT_LIST_HEAD(&timer->samples);
			hash_add(sess->timers, &timer->node, (unsigned long)timer->name);
			sess->nr_timers++;
		}

		return timer;
#else
		return NULL;
#endif
}

int virtaccel_timer_start(char *name, struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;

	if (!profiling)
		return 0;

	if (!sess) {
		pr_warn("virtio-accel session not found. Timer '%s' will not be created.",
				name);
		return 0;
	}

	timer = timer_get_by_name(name, sess);
	if (timer == NULL) {
		timer = timer_create_and_add(name, sess);
		if (!timer)
			return -ENOMEM;
		timer->nr_samples = 0;
	}

	timer->nr_samples += timer_sample_add(timer);
#endif
	return 0;
}

void virtaccel_timer_stop(char *name, struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;

	if (!profiling)
		return;

	if (!sess)
		return;

	timer = timer_get_by_name(name, sess);
	if (!timer)
		return;

	timer_sample_time(timer);
#endif
}

void virtaccel_timer_del(struct virtio_accel_timer *timer)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL, *tmp;

	if (!profiling)
		return;

	if (!timer)
		return;

	list_for_each_entry_safe(sample, tmp, &timer->samples, node) {
		list_del(&sample->node);
		kfree(sample);
	}

	hash_del(&timer->node);
	kfree(timer);
#endif
}

void virtaccel_timers_del_by_name(char *name, struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;

	if (!profiling)
		return;

	if (!sess)
		return;

	timer = timer_get_by_name(name, sess);
	if (!timer)
		return;

	virtaccel_timer_del(timer);
	sess->nr_timers--;
#endif
}


void virtaccel_timers_del_all(struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	struct hlist_node *tmp;
	int bkt;

	if (!profiling)
		return;

	if (!sess)
		return;

	hash_for_each_safe(sess->timers, bkt, tmp, timer, node) {
		virtaccel_timer_del(timer);
	}
	sess->nr_timers = 0;
#endif
}


#define FORMAT_STRING "[virtio-accel] %s: total_time: %lld nsec nr_entries: %d\n"

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

	list_for_each_entry_safe(sample, tmp, &timer->samples, node) {
		total += ktime_to_ns(sample->time);
	}

	return total;
#else
	return 0;
#endif
}

void virtaccel_timers_print_by_name(char *name, struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = timer_get_by_name(name, sess);
	s64 time;

	if (!profiling)
		return;

	if (timer == NULL)
		return;

	time = timer_sample_get_last(timer);
	printk(KERN_INFO FORMAT_STRING, timer->name, time, 1);
#endif
}

void virtaccel_timers_print_all(struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt;

	if (!profiling)
		return;

	if (!sess)
		return;

	hash_for_each(sess->timers, bkt, timer, node) {
		s64 time = timer_sample_get_last(timer);
		printk(KERN_INFO FORMAT_STRING, timer->name, time, 1);
	}
#endif
}

void virtaccel_timers_print_all_total(struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt;

	if (!profiling)
		return;

	if (!sess)
		return;

	hash_for_each(sess->timers, bkt, timer, node) {
		s64 time = timer_sample_get_total(timer);
		printk(KERN_INFO FORMAT_STRING, timer->name, time, 1);
	}
#endif
}

int virtaccel_timers_print_by_name_to_buf(char **buf,
		char *name, struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	int ssize = 0;
	s64 time = 0;
	struct virtio_accel_timer *timer = NULL;

	if (!profiling)
		return 0;

	if (!sess)
		return 0;

	timer = timer_get_by_name(name, sess);
	if (timer == NULL)
		return 0;

	time = timer_sample_get_last(timer);
	ssize = snprintf(NULL, 0, FORMAT_STRING,
			timer->name, time, 1) + 1;

	if (buf == NULL)
		return ssize;

	*buf = kzalloc(ssize, GFP_KERNEL);
	if (!*buf)
		return -ENOMEM;

	return scnprintf(*buf, ssize, FORMAT_STRING,
			timer->name, time, 1) + 1;
#endif
	return 0;
}

int virtaccel_timers_print_all_to_buf(char **buf,
		struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt, ssize = 0, size = 0;
	s64 time = 0;

	if (!profiling)
		return 0;

	if (!sess)
		return 0;

	hash_for_each(sess->timers, bkt, timer, node) {
		time = timer_sample_get_last(timer);
		ssize += snprintf(NULL, 0, FORMAT_STRING,
				timer->name, time, timer->nr_samples) + 1;
	}

	if (buf == NULL)
		return ssize;

	*buf = kzalloc(ssize, GFP_KERNEL);
	if (!*buf)
		return -ENOMEM;

	hash_for_each(sess->timers, bkt, timer, node) {
		time = timer_sample_get_last(timer);
		size += scnprintf(*buf+size, ssize-size, FORMAT_STRING,
				timer->name, time, 1) + 1;
	}

	return size;
#endif
	return 0;
}

int virtaccel_timers_print_all_total_to_buf(struct accel_arg *tbuf,
		struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt, ssize = 0, size = 0;
	s64 time = 0;

	if (!profiling)
		return 0;

	if (!sess)
		return 0;

	hash_for_each(sess->timers, bkt, timer, node) {
		time = timer_sample_get_total(timer);
		ssize += snprintf(NULL, 0, FORMAT_STRING,
				timer->name, time, timer->nr_samples) + 1;
	}

	if (tbuf == NULL)
		return ssize;

	tbuf->buf = kzalloc(tbuf->len, GFP_KERNEL);
	if (!tbuf->buf)
		return -ENOMEM;

	hash_for_each(sess->timers, bkt, timer, node) {
		time = timer_sample_get_total(timer);
		size += scnprintf(tbuf->buf+size, tbuf->len-size, FORMAT_STRING,
				timer->name, time, timer->nr_samples);
	}

	return size;
#endif
	return 0;
}

static int timer_sample_virtio_to_accel(struct accel_prof_sample *accel_samples,
		int nr_accel_samples, struct virtio_accel_timer *timer)
{
#ifdef PROFILING
	struct virtio_accel_timer_sample *sample = NULL, *tmp;
	int i = 0;

	list_for_each_entry_safe(sample, tmp, &timer->samples, node) {
		if (i == nr_accel_samples) {
			pr_warn("not all virtio-accel samples for %s can be returned (allocated: %d vs total: %d)",
					timer->name, nr_accel_samples, timer->nr_samples);
			break;
		}

		accel_samples[i].start = ktime_to_ns(sample->start);
		accel_samples[i].time = ktime_to_ns(sample->time);
		i++;
	}

	return i;
#else
	return 0;
#endif
}

#define TIMERS_NAME_PREFIX "[virtio-accel]"
int virtaccel_timers_virtio_to_accel(struct accel_prof_region *accel_timers,
		int nr_accel_timers, struct virtio_accel_sess *sess)
{
#ifdef PROFILING
	struct virtio_accel_timer *timer = NULL;
	int bkt, i = 0;

	if (!profiling)
		return 0;

	if (nr_accel_timers < 1)
		return 0;

	hash_for_each(sess->timers, bkt, timer, node) {
		if (i == nr_accel_timers) {
			pr_warn("not all virtio-accel timers can be returned (allocated: %d vs total: %d)",
					nr_accel_timers, sess->nr_timers);
			break;
		}

		snprintf(accel_timers[i].name, TIMERS_NAME_MAX, "%s %s",
				TIMERS_NAME_PREFIX, timer->name);
		accel_timers[i].nr_entries =
			timer_sample_virtio_to_accel(accel_timers[i].samples,
				accel_timers[i].size, timer);
		i++;
	}

	return i;
#else
	return 0;
#endif
}
