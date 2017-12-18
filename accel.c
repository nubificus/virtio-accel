#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "accel.h"
#include "virtio_accel-common.h"

static long accel_dev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long _arg)
{
	void __user *arg = (void __user *)_arg;
	struct virtio_accel_file *vaccel_file = filp->private_data;
	struct virtio_accel *vaccel = vaccel_file->vaccel;
	struct virtio_accel_req *req;
	struct accel_session *sess = NULL;
	struct accel_op *op = NULL;
	int ret;

	switch (cmd) {
	case ACCIOC_CRYPTO_SESS_CREATE:
		req = kzalloc(sizeof(*req), GFP_KERNEL);
		if (!req)
			return -ENOMEM;
		
		sess = kzalloc(sizeof(*sess), GFP_KERNEL);
		if (!sess)
			return -ENOMEM;
		if (unlikely(copy_from_user(sess, arg, sizeof(*sess)))) {
			kfree(sess);
			ret = -EFAULT;
			goto err_req;
		}
		
		req->usr = arg;
		req->priv = sess;
		req->vaccel = vaccel;
		ret = virtaccel_req_crypto_create_session(req);
		if (ret != -EINPROGRESS)
			goto err_req;
		break;
	case ACCIOC_CRYPTO_SESS_DESTROY:
		req = kzalloc(sizeof(*req), GFP_KERNEL);
		if (!req)
			return -ENOMEM;

		sess = kzalloc(sizeof(*sess), GFP_KERNEL);
		if (!sess)
			return -ENOMEM;
		if (unlikely(copy_from_user(sess, arg, sizeof(*sess)))) {
			kfree(sess);
			ret = -EFAULT;
			goto err_req;
		}
		
		req->priv = sess;
		req->vaccel = vaccel;
		ret = virtaccel_req_crypto_destroy_session(req);
		if (ret != -EINPROGRESS)
			goto err_req;
		break;
	case ACCIOC_CRYPTO_ENCRYPT:
	case ACCIOC_CRYPTO_DECRYPT:
		req = kzalloc(sizeof(*req), GFP_KERNEL);
		if (!req)
			return -ENOMEM;
	
		op = kzalloc(sizeof(*op), GFP_KERNEL);
		if (!op)
			return -ENOMEM;
		if (unlikely(copy_from_user(op, arg, sizeof(*op)))) {
			kfree(op);
			ret = -EFAULT;
			goto err_req;
		}
	
		req->priv = op;
		req->vaccel = vaccel;
		if (cmd == ACCIOC_CRYPTO_ENCRYPT)
			ret = virtaccel_req_crypto_encrypt(req);
		else
			ret = virtaccel_req_crypto_decrypt(req);
		if (ret != -EINPROGRESS)
			goto err_req;

		break;
	default:
		pr_err("Invalid IOCTL\n");
		ret = -EFAULT;
		goto err;
	}

	pr_debug("Waiting to complete request\n");
	wait_for_completion(&req->completion);
	reinit_completion(&req->completion);
	pr_debug("Completed request\n");

	ret = req->ret;
	kzfree(req);	
	return ret;

err_req:
	kzfree(req);
err:
	return ret;
}

static int accel_dev_open(struct inode *inode, struct file *filp)
{
	struct virtio_accel *vaccel = virtaccel_devmgr_get_first();
	struct virtio_accel_file *vaccel_file;

	if (!vaccel)
		return -ENODEV;

	vaccel_file = kzalloc(sizeof(*vaccel_file), GFP_KERNEL);
	if (!vaccel_file)
		return -ENOMEM;

	vaccel->dev_minor = iminor(inode);

	INIT_LIST_HEAD(&vaccel_file->sessions);
	vaccel_file->vaccel = vaccel;
	filp->private_data = vaccel_file;

	return nonseekable_open(inode, filp);
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
	
	pr_debug("Initializing character device...\n");
	ret = misc_register(&accel_dev);
	if (unlikely(ret)) {
		pr_err("registration of /dev/accel failed\n");
		return ret;
	}

	return 0;
}

void accel_dev_destroy(void)
{
	misc_deregister(&accel_dev);
}
