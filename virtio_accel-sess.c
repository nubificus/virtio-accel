// SPDX-License-Identifier: GPL-2.0

#include <linux/list.h>
#include <linux/slab.h>

#include "virtio_accel-prof.h"

struct virtio_accel_sess *
virtaccel_session_create_and_add(u64 id, struct virtio_accel_req *req)
{
	struct virtio_accel_sess *sess = kzalloc(sizeof(*sess), GFP_KERNEL);

	if (!id)
		return NULL;

	if (sess) {
		sess->id = id;
		sess->nr_timers = 0;
		virtaccel_timers_init(sess);
		list_add_tail(&sess->node, &req->vaccel->sessions);
	}

	return sess;
}

void virtaccel_session_delete(u64 id, struct virtio_accel_req *req)
{
	struct virtio_accel_sess *s = NULL;
	struct virtio_accel_sess *tmp;

	if (!id)
		return;

	list_for_each_entry_safe(s, tmp, &req->vaccel->sessions, node)
	{
		if (s->id == id) {
			list_del(&s->node);
			virtaccel_timers_free(s);
			kfree(s);
		}
	}
}

struct virtio_accel_sess *
virtaccel_session_get_by_id(u64 id, struct virtio_accel_req *req)
{
	struct virtio_accel_sess *s = NULL;
	struct virtio_accel_sess *tmp;

	if (!id)
		return NULL;

	list_for_each_entry_safe(s, tmp, &req->vaccel->sessions, node)
	{
		if (s->id == id) {
			return s;
		}
	}
	return NULL;
}
