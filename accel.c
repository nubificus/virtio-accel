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
#include "accel-internal.h"
#include "virtio_accel-common.h"
#include "virtio_accel-prof.h"

static int accel_op_req_new(struct accel_op_req **op_req,
			    struct accel_op __user *op)
{
	struct accel_op_req *req;

	if (!op_req)
		return -EINVAL;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->out = NULL;
	req->in = NULL;

	if (!op) {
		*op_req = req;
		return 0;
	}

	if (unlikely(copy_from_user(&req->u_op, op, sizeof(req->u_op))))
		return -EFAULT;

	if (req->u_op.out_nr) {
		req->out = memdup_user(u64_to_user_ptr(req->u_op.out),
				       req->u_op.out_nr * sizeof(*req->out));
		if (IS_ERR(req->out))
			return PTR_ERR(req->out);
	}

	if (req->u_op.in_nr) {
		req->in = memdup_user(u64_to_user_ptr(req->u_op.in),
				      req->u_op.in_nr * sizeof(*req->in));
		if (IS_ERR(req->in)) {
			kfree(req->out);
			return PTR_ERR(req->in);
		}
	}

	*op_req = req;
	return 0;
}

static void accel_op_req_delete(struct accel_op_req *op_req)
{
	if (!op_req)
		return;

	kfree(op_req->out);
	kfree(op_req->in);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	kzfree(op_req);
#else
	kfree_sensitive(op_req);
#endif
}

static int parse_ioctl_arg(void __user *arg, unsigned int cmd,
			   struct accel_op_req **op_req)
{
	void __user *op = NULL;
	int virtio_cmd;
	int ret;

	switch (cmd) {
	case ACCEL_SESS_CREATE:
		op = arg;
		virtio_cmd = VIRTIO_ACCEL_CMD_CREATE_SESSION;
		break;
	case ACCEL_SESS_DESTROY:
		virtio_cmd = VIRTIO_ACCEL_CMD_DESTROY_SESSION;
		break;
	case ACCEL_DO_OP:
		op = arg;
		virtio_cmd = VIRTIO_ACCEL_CMD_DO_OP;
		break;
	case ACCEL_GET_TIMERS:
		op = arg;
		virtio_cmd = VIRTIO_ACCEL_CMD_GET_TIMERS;
		break;
	default:
		virtaccel_err("Invalid IOCTL\n");
		return -ENOIOCTLCMD;
	}

	ret = accel_op_req_new(op_req, op);
	if (ret)
		return ret;

	if (!op &&
	    unlikely(get_user((*op_req)->u_op.session_id, (u64 __user *)arg)))
		return -EFAULT;

	return virtio_cmd;
}

static long accel_dev_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg_p)
{
	void __user *arg = (void __user *)arg_p;
	struct virtio_accel_file *vaccel_file = file->private_data;
	struct virtio_accel_req *req;
	struct accel_op_req *op_req;
	struct virtio_accel_sess *sess = NULL;
	u32 virtio_cmd;
	int ret;

	req = virtaccel_req_new(vaccel_file->vaccel, arg);
	if (!req)
		return -ENOMEM;

	ret = parse_ioctl_arg(arg, cmd, &op_req);
	if (ret < 0)
		goto err_req;

	virtio_cmd = (u32)ret;
	req->priv = op_req;

	if (cmd == ACCEL_DO_OP) {
		sess = virtaccel_session_get_by_id(op_req->u_op.session_id,
						   req);
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

	accel_op_req_delete(op_req);
	req->priv = NULL;

	virtaccel_req_delete(req);
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
