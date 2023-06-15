#include <linux/slab.h>
#include <linux/list.h>

#include "virtio_accel-prof.h"


struct virtio_accel_sess *virtaccel_session_create_and_add(
		struct accel_session *accel_sess, struct virtio_accel_req *req)
{
	struct virtio_accel_sess *sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (sess) {
		sess->id = accel_sess->id;
		sess->nr_timers = 0;
		virtaccel_timers_init(sess);
		list_add_tail(&sess->node, &req->vaccel->sessions);
	}

	return sess;
}

void virtaccel_session_delete(struct accel_session *accel_sess,
		struct virtio_accel_req *req)
{
	struct virtio_accel_sess *s = NULL, *tmp;

	if (!accel_sess)
		return;

	list_for_each_entry_safe(s, tmp, &req->vaccel->sessions, node) {
		if (s->id == accel_sess->id) {
			list_del(&s->node);
			virtaccel_timers_free(s);
			kfree(s);
		}
	}
}

struct virtio_accel_sess *virtaccel_session_get_by_id(u32 id,
		struct virtio_accel_req *req)
{
	struct virtio_accel_sess *s = NULL, *tmp;

	list_for_each_entry_safe(s, tmp, &req->vaccel->sessions, node) {
		if (s->id == id) {
			return s;
		}
	}
	return NULL;
}
