// SPDX-License-Identifier: GPL-2.0

#include <linux/cdev.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/container_of.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/virtio.h>

#include "cdev.h"
#include "common.h"
#include "core.h"
#include "op_request.h"
#include "profiler.h"
#include "request.h"
#include "session.h"
#include <linux/virtio_accel.h>

enum { MIN_MS = 60 * 1000 };

static unsigned int request_timeout_ms = MIN_MS;
module_param(request_timeout_ms, uint, S_IRUGO);
MODULE_PARM_DESC(request_timeout_ms, "virtio-accel request timeout (ms)");

static int parse_ioctl_arg(void __user *arg, unsigned int cmd,
			   struct virtio_accel_op_request **op_req)
{
	void __user *op = NULL;
	int virtio_cmd;
	int ret;

	switch (cmd) {
	case VIRTIO_ACCEL_CREATE_SESSION:
		op = arg;
		virtio_cmd = VIRTIO_ACCEL_CMD_CREATE_SESSION;
		break;
	case VIRTIO_ACCEL_DESTROY_SESSION:
		virtio_cmd = VIRTIO_ACCEL_CMD_DESTROY_SESSION;
		break;
	case VIRTIO_ACCEL_DO_OP:
		op = arg;
		virtio_cmd = VIRTIO_ACCEL_CMD_DO_OP;
		break;
	case VIRTIO_ACCEL_GET_TIMERS:
		op = arg;
		virtio_cmd = VIRTIO_ACCEL_CMD_GET_TIMERS;
		break;
	default:
		vacl_err("Invalid IOCTL\n");
		return -ENOIOCTLCMD;
	}

	ret = virtio_accel_op_request_new(op_req, op);
	if (ret)
		return ret;

	if (!op &&
	    unlikely(get_user((*op_req)->u_op.session_id, (u64 __user *)arg)))
		return -EFAULT;

	return virtio_cmd;
}

static long virtio_accel_cdev_ioctl(struct file *file, unsigned int cmd,
				    unsigned long arg_p)
{
	void __user *arg = (void __user *)arg_p;
	struct virtio_accel *vacl = file->private_data;
	struct virtio_accel_request *req = NULL;
	struct virtio_accel_op_request *op_req = NULL;
	struct virtio_accel_session *sess = NULL;
	u32 virtio_cmd;
	int ret;

	ret = parse_ioctl_arg(arg, cmd, &op_req);
	if (ret < 0)
		return ret;

	virtio_cmd = (u32)ret;

	req = virtio_accel_request_new(vacl, op_req);
	if (!req)
		goto err_req;

	if (cmd == VIRTIO_ACCEL_DO_OP) {
		sess = virtio_accel_session_get_by_id(op_req->u_op.session_id,
						      req);
		virtio_accel_profiler_timer_start(sess, "request submit");
	}

	ret = virtio_accel_request_submit(req, virtio_cmd);
	if (ret != -EINPROGRESS)
		goto err_req;

	vacl_debug("Waiting for request to complete\n");
	ret = wait_for_completion_killable_timeout(
		&req->completion, msecs_to_jiffies(request_timeout_ms));
	if (ret <= 0) {
		if (!ret)
			ret = -ETIMEDOUT;
		goto err_req;
	}

	virtio_accel_profiler_timer_stop(sess, "request submit");

	virtio_accel_profiler_timer_start(sess, "handle result");
	virtio_accel_request_handle_result(req);
	virtio_accel_profiler_timer_stop(sess, "handle result");

	vacl_debug("Request completed\n");

	virtio_accel_profiler_timer_start(sess, "copy to user");
	ret = virtio_accel_op_request_copy_to_user(op_req, arg, cmd);
	if (req->ret)
		ret = req->ret;
	virtio_accel_profiler_timer_stop(sess, "copy to user");

err_req:
	virtio_accel_profiler_timer_stop(sess, "request submit");

	virtio_accel_op_request_delete(op_req);
	req->op_req = NULL;

	virtio_accel_request_delete(req);
	return ret;
}

static int virtio_accel_cdev_open(struct inode *inode, struct file *file)
{
	struct virtio_accel *vacl;

	vacl = container_of(file->private_data, struct virtio_accel, cdev);
	if (!vacl)
		return -ENODEV;

	file->private_data = vacl;
	return nonseekable_open(inode, file);
}

static int virtio_accel_cdev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations virtio_accel_cdev_fops = {
	.owner = THIS_MODULE,
	.open = virtio_accel_cdev_open,
	.release = virtio_accel_cdev_release,
	.unlocked_ioctl = virtio_accel_cdev_ioctl,
};

int virtio_accel_cdev_init(struct virtio_accel *vacl)
{
	int ret;

	vacl->cdev.minor = MISC_DYNAMIC_MINOR, vacl->cdev.name = "virtio-accel",
	vacl->cdev.fops = &virtio_accel_cdev_fops,
	vacl->cdev.mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH |
			  S_IWOTH,
	vacl->cdev.parent = &vacl->vdev->dev;

	ret = misc_register(&vacl->cdev);
	if (unlikely(ret))
		vacl_err("Failed to register /dev/virtio-accel\n");

	return ret;
}

void virtio_accel_cdev_cleanup(struct virtio_accel *vacl)
{
	misc_deregister(&vacl->cdev);
}
