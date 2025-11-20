// SPDX-License-Identifier: GPL-2.0

#include <linux/gfp_types.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "session.h"
#include "core.h"
#include "profiler.h"

struct virtio_accel_session *
virtio_accel_session_create_and_add(struct virtio_accel *vacl, u64 id)
{
	struct virtio_accel_session *sess = kzalloc(sizeof(*sess), GFP_KERNEL);

	if (sess) {
		sess->id = id;
		sess->nr_timers = 0;
		virtio_accel_profiler_timers_init(sess);
		list_add_tail(&sess->node, &vacl->sessions);
	}

	return sess;
}

void virtio_accel_session_delete(struct virtio_accel *vacl, u64 id)
{
	struct virtio_accel_session *s = NULL;
	struct virtio_accel_session *tmp;

	list_for_each_entry_safe(s, tmp, &vacl->sessions, node)
	{
		if (s->id == id) {
			list_del(&s->node);
			virtio_accel_profiler_timers_free(s);
			kfree(s);
		}
	}
}

struct virtio_accel_session *
virtio_accel_session_get_by_id(struct virtio_accel *vacl, u64 id)
{
	struct virtio_accel_session *s = NULL;
	struct virtio_accel_session *tmp;

	list_for_each_entry_safe(s, tmp, &vacl->sessions, node)
	{
		if (s->id == id) {
			return s;
		}
	}
	return NULL;
}
