#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "accel.h"
#include "virtio-accel.h"

static long accel_dev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long _arg)
{
	void __user *arg = (void __user *)_arg;
	struct virtio_accel_file *vaccel_file = filp->private_data;
	struct virtio_accel *vaccel = vaccel_file->vaccel;
	struct virtio_accel_request *req;
	struct virtqueue *vq = vaccel->vq;
	struct accel_session sess;

	switch (cmd) {
	case ACCIOC_SESS_CREATE:
		if (unlikely(copy_from_user(&sess, arg, sizeof(sess))))
			return -EFAULT;
		
		req = kzalloc(sizeof(*req), GFP_KERNEL);
		if (!req)
			return -ENOMEM;
		ret = virtio_accel_req_create_session(req, vaccel, &sess);
		if (!req) {
			kfree(req);
			return ret;
		}
	}

	ret = virtio_accel_do_req(req);
	if (req < 0) {
		kfree(req);
		return ret;
	}

	return -EINPROGRESS;
}

static int accel_dev_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct virtio_accel *vaccel = virtio_accel_devmgr_get_first();
	struct virtio_accel_file *vaccel_file;

	if (!virtio_accel)
		return -ENODEV;

	vaccel_file = kzalloc(sizeof(*vaccel_file), GFP_KERNEL);
	if (!vaccel_file)
		return -ENOMEM;

	vaccel->dev_minor = iminor(inode);

	INIT_LIST_HEAD(&vaccel_file->sessions);
	vaccel_file->vaccel = vaccel;
	filp->private_data = vaccel_file;

	return nonseekable_open(inode, file);
}

static int accel_dev_release(struct inode *inode, struct file *filp)
{
	struct virtio_accel_file *vaccel_file = filp->private_data;

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
	.mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH,
};

int accel_dev_init(void)
{
	int ret;
	
	debug("Initializing character device...");
	ret = misc_register(&accel_dev);
	if (unlikely(ret)) {
		pr_err("registration of /dev/accel failed\n");
		return ret;
	}

	return 0;
}

void crypto_chrdev_destroy(void)
{
	misc_deregister(&accel_dev);
}
