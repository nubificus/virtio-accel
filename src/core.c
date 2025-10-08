// SPDX-License-Identifier: GPL-2.0

#include <linux/completion.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/gfp_types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "core.h"
#include "cdev.h"
#include "common.h"
#include "request.h"
#include "version.h"
#include <linux/virtio_accel.h>
#include <linux/virtio_id.h>

static void virtio_accel_dataq_callback(struct virtqueue *vq)
{
	struct virtio_accel *vacl = vq->vdev->priv;
	struct virtio_accel_request *req;
	unsigned long flags;
	unsigned int len;
	unsigned int qid = vq->index;

	spin_lock_irqsave(&vacl->vqs[qid].lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
			vacl_debug("Response status=%u\n", req->status);

			if (req->parent) {
				// Chunk completion
				struct virtio_accel_request *parent =
					req->parent;

				spin_unlock_irqrestore(&vacl->vqs[qid].lock,
						       flags);
				virtio_accel_request_delete(req);

				if (atomic_read(&parent->chunk_count)) {
					spin_lock_irqsave(&vacl->vqs[qid].lock,
							  flags);
					continue;
				}

				req = parent;
				spin_lock_irqsave(&vacl->vqs[qid].lock, flags);
			}

			// Regular request completion
			switch (req->status) {
			case VIRTIO_ACCEL_OK:
				req->ret = 0;
				break;
			case VIRTIO_ACCEL_INVSESS:
			case VIRTIO_ACCEL_ERR:
				req->ret = -EINVAL;
				break;
			case VIRTIO_ACCEL_BADMSG:
				req->ret = -EBADMSG;
				break;
			default:
				req->ret = -EIO;
				break;
			}

			spin_unlock_irqrestore(&vacl->vqs[qid].lock, flags);
			if (!completion_done(&req->completion))
				complete_all(&req->completion);
			else
				virtio_accel_request_delete(req);
			spin_lock_irqsave(&vacl->vqs[qid].lock, flags);
		}
	} while (!virtqueue_enable_cb(vq));
	spin_unlock_irqrestore(&vacl->vqs[qid].lock, flags);
}

static int virtio_accel_init_vqs(struct virtio_accel *vacl)
{
	struct virtio_device *vdev = vacl->vdev;
	struct virtqueue **vqs;
	vq_callback_t **callbacks;
	const char **names;
	unsigned short i;
	unsigned short num_vqs;
	int ret = -ENOMEM;

	virtio_cread(vdev, struct virtio_accel_config, num_queues, &num_vqs);
	if (num_vqs != 1) {
		dev_err(&vdev->dev, "Only a single virtqueue is supported\n");
		return -EINVAL;
	}

	vacl->vqs = kmalloc_array(num_vqs, sizeof(*vacl->vqs), GFP_KERNEL);
	if (!vacl->vqs)
		return -ENOMEM;

	/* Allocate space for find_vqs parameters */
	vqs = kcalloc(num_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_free_dev_vqs;

	callbacks = kcalloc(num_vqs, sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_free_vqs;

	names = kcalloc(num_vqs, sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_free_callbacks;

	/* Allocate/initialize parameters for data virtqueues */
	for (i = 0; i < num_vqs; i++) {
		callbacks[i] = virtio_accel_dataq_callback;
		snprintf(vacl->vqs[i].name, sizeof(vacl->vqs[i].name), "q.%d",
			 i);
		names[i] = vacl->vqs[i].name;
	}

	ret = virtio_find_vqs(vacl->vdev, num_vqs, vqs, callbacks, names, NULL);
	if (ret)
		goto err_free_names;

	for (i = 0; i < num_vqs; i++) {
		spin_lock_init(&vacl->vqs[i].lock);
		vacl->vqs[i].vq = vqs[i];
	}
	vacl->num_vqs = (unsigned int)num_vqs;

	kfree(names);
	kfree(callbacks);
	kfree(vqs);

	return 0;

err_free_names:
	kfree(names);
err_free_callbacks:
	kfree(callbacks);
err_free_vqs:
	kfree(vqs);
err_free_dev_vqs:
	kfree(vacl->vqs);
	return ret;
}

static void virtio_accel_del_vqs(struct virtio_accel *vacl)
{
	struct virtio_device *vdev = vacl->vdev;

	vdev->config->del_vqs(vdev);
	kfree(vacl->vqs);
}

static int virtio_accel_probe(struct virtio_device *vdev)
{
	struct virtio_accel *vacl;
	unsigned short max_req_descriptors;
	int ret = -EFAULT;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	if (num_possible_nodes() > 1 && dev_to_node(&vdev->dev) < 0) {
		dev_err(&vdev->dev, "Invalid NUMA configuration\n");
		return -EINVAL;
	}

	vacl = kzalloc_node(sizeof(*vacl), GFP_KERNEL, dev_to_node(&vdev->dev));
	if (!vacl)
		return -ENOMEM;

	vacl->owner = THIS_MODULE;
	vacl = vdev->priv = vacl;
	vacl->vdev = vdev;
	INIT_LIST_HEAD(&vacl->sessions);
	atomic64_set(&vacl->next_request_id, 1);

	ret = virtio_accel_init_vqs(vacl);
	if (ret) {
		dev_err(&vdev->dev, "Failed to initialize vqs\n");
		goto err_free;
	}

	virtio_cread(vdev, struct virtio_accel_config, max_req_descriptors,
		     &max_req_descriptors);
	if (max_req_descriptors <= 2) {
		dev_err(&vdev->dev, "Max request descriptors must be > 2\n");
		ret = -EINVAL;
		goto err_free_vqs;
	}
	vacl->max_req_descriptors = (unsigned int)max_req_descriptors;

	ret = virtio_accel_cdev_init(vacl);
	if (ret) {
		dev_err(&vdev->dev, "Failed to initialize character device\n");
		goto err_free_vqs;
	}

	virtio_device_ready(vdev);
	dev_info(&vdev->dev, "virtio-accel is ready\n");

	return 0;

err_free_vqs:
	vacl->vdev->config->reset(vdev);
	virtio_accel_del_vqs(vacl);
err_free:
	kfree(vacl);
	return ret;
}

static void virtio_accel_free_unused_reqs(struct virtio_accel *vacl)
{
	struct virtio_accel_request *req;

	while ((req = virtqueue_detach_unused_buf(vacl->vqs[0].vq)) != NULL) {
		if (!completion_done(&req->completion))
			complete_all(&req->completion);
		else
			virtio_accel_request_delete(req);
	}
}

static void virtio_accel_remove(struct virtio_device *vdev)
{
	struct virtio_accel *vacl = vdev->priv;

	dev_info(&vdev->dev, "Start virtio-accel remove\n");
	virtio_reset_device(vdev);

	virtio_accel_free_unused_reqs(vacl);
	virtio_accel_del_vqs(vacl);
	virtio_accel_cdev_cleanup(vacl);
	kfree(vacl);
}

static unsigned int features[] = {
	/* none */
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_ACCEL, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_accel_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.id_table = id_table,
	.probe = virtio_accel_probe,
	.remove = virtio_accel_remove,
};

static int __init virtio_accel_init(void)
{
	int ret = register_virtio_driver(&virtio_accel_driver);
	if (ret)
		vacl_err("Failed to register virtio driver\n");

	return ret;
}

static void __exit virtio_accel_exit(void)
{
	unregister_virtio_driver(&virtio_accel_driver);
}

module_init(virtio_accel_init);
module_exit(virtio_accel_exit);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("virtio-accel device driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(VIRTIO_ACCEL_VERSION);
