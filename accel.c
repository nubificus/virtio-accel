// SPDX-License-Identifier: GPL-2.0

#include <linux/cdev.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/wait.h>

#include "accel.h"
#include "virtio_accel-common.h"
#include "virtio_accel-prof.h"

static struct accel_op *accel_op_new(void)
{
	struct accel_op *op = NULL;

	op = kmalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		return NULL;

	op->session_id = 0;
	op->op_code = 0;
	op->out_nr = 0;
	op->in_nr = 0;
	op->out = NULL;
	op->in = NULL;
	op->ret = 0;

	return op;
}

static int parse_ioctl_arg(void __user *arg, unsigned int cmd,
			   struct accel_op *op)
{
	switch (cmd) {
	case ACCEL_SESS_CREATE:
		if (unlikely(copy_from_user(op, arg, sizeof(*op))))
			return -EFAULT;

		return VIRTIO_ACCEL_CMD_CREATE_SESSION;
	case ACCEL_SESS_DESTROY:
		if (unlikely(copy_from_user(&op->session_id, arg,
					    sizeof(op->session_id))))
			return -EFAULT;

		return VIRTIO_ACCEL_CMD_DESTROY_SESSION;
	case ACCEL_DO_OP:
		if (unlikely(copy_from_user(op, arg, sizeof(*op))))
			return -EFAULT;

		return VIRTIO_ACCEL_CMD_DO_OP;
	case ACCEL_GET_TIMERS:
		if (unlikely(copy_from_user(op, arg, sizeof(*op))))
			return -EFAULT;

		return VIRTIO_ACCEL_CMD_GET_TIMERS;
	default:
		virtaccel_err("Invalid IOCTL\n");
		return -ENOIOCTLCMD;
	}
}

static long accel_dev_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg_p)
{
	void __user *arg = (void __user *)arg_p;
	struct virtio_accel_file *vaccel_file = file->private_data;
	struct virtio_accel_req *req;
	struct accel_op *op;
	struct virtio_accel_sess *sess = NULL;
	u32 virtio_cmd;
	int ret;

	req = virtaccel_req_new(vaccel_file->vaccel, arg);
	if (!req)
		return -ENOMEM;

	op = accel_op_new();
	if (!op) {
		ret = -ENOMEM;
		goto err_req;
	}
	req->priv = op;

	ret = parse_ioctl_arg(arg, cmd, op);
	if (ret < 0)
		goto err_req;
	else
		virtio_cmd = (u32)ret;

	if (cmd == ACCEL_DO_OP) {
		sess = virtaccel_session_get_by_id(op->session_id, req);
		virtaccel_timer_start("accel > do op", sess);
	}

	ret = virtaccel_req_operation(req, virtio_cmd);
	if (ret != -EINPROGRESS)
		goto err_req;

	virtaccel_debug("Waiting for request to complete\n");
	ret = wait_for_completion_killable(&req->completion);
	if (ret)
		goto err_req;

	virtaccel_req_handle_result(req);
	ret = req->ret;
	virtaccel_debug("Request completed\n");

err_req:
	virtaccel_timer_stop("accel > do op", sess);
	//virtaccel_timer_print_all_total(sess);

	virtaccel_req_delete(req);
	kfree(op);
	return ret;
}

static int accel_dev_open(struct inode *inode, struct file *file)
{
	struct virtio_accel *vaccel = virtaccel_devmgr_get_first();
	struct virtio_accel_file *vaccel_file;

	if (!vaccel)
		return -ENODEV;

	vaccel_file = kzalloc(sizeof(*vaccel_file), GFP_KERNEL);
	if (!vaccel_file)
		return -ENOMEM;

	vaccel->dev_minor = iminor(inode);

	vaccel_file->vaccel = vaccel;
	file->private_data = vaccel_file;

	return nonseekable_open(inode, file);
}

static int accel_dev_release(struct inode *inode, struct file *file)
{
	struct virtio_accel_file *vaccel_file = file->private_data;

	kfree(vaccel_file);
	return 0;
}

static const struct file_operations accel_dev_fops = {
	.owner = THIS_MODULE,
	.open = accel_dev_open,
	.release = accel_dev_release,
	.unlocked_ioctl = accel_dev_ioctl,
};

static struct miscdevice accel_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "accel",
	.fops = &accel_dev_fops,
	.mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
};

int accel_dev_init(void)
{
	int ret;

	virtaccel_debug("Initializing character device...\n");
	ret = misc_register(&accel_dev);
	if (unlikely(ret)) {
		virtaccel_err("registration of /dev/accel failed\n");
		return ret;
	}

	return 0;
}

void accel_dev_destroy(void)
{
	misc_deregister(&accel_dev);
}
