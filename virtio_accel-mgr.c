/* Management for virtio accel devices (refer to adf_dev_mgr.c).
  */

#include <linux/device.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/virtio.h>

#include "accel.h"
#include "virtio_accel-common.h"

static LIST_HEAD(virtaccel_table);
static uint32_t num_devices;

/* The table_lock protects the above global list and num_devices */
static DEFINE_MUTEX(table_lock);

#define VIRTIO_ACCEL_MAX_DEVICES 32

/*
 * virtaccel_devmgr_add_dev() - Add vaccel_dev to the acceleration
 * framework.
 * @vaccel_dev:  Pointer to virtio accel device.
 *
 * Function adds virtio accel device to the global list.
 * To be used by virtio accel device specific drivers.
 *
 * Return: 0 on success, error code otherwise.
 */
int virtaccel_devmgr_add_dev(struct virtio_accel *vaccel_dev)
{
	struct list_head *itr;

	mutex_lock(&table_lock);
	if (num_devices == VIRTIO_ACCEL_MAX_DEVICES) {
		pr_info("virtio_accel: only support up to %d devices\n",
			VIRTIO_ACCEL_MAX_DEVICES);
		mutex_unlock(&table_lock);
		return -EFAULT;
	}

	list_for_each(itr, &virtaccel_table)
	{
		struct virtio_accel *ptr =
			list_entry(itr, struct virtio_accel, list);

		if (ptr == vaccel_dev) {
			mutex_unlock(&table_lock);
			return -EEXIST;
		}
	}
	atomic_set(&vaccel_dev->ref_count, 0);
	list_add_tail(&vaccel_dev->list, &virtaccel_table);
	vaccel_dev->dev_id = num_devices++;
	mutex_unlock(&table_lock);
	return 0;
}

struct list_head *virtaccel_devmgr_get_head(void)
{
	return &virtaccel_table;
}

/*
 * virtaccel_devmgr_rm_dev() - Remove vaccel_dev from the acceleration
 * framework.
 * @vaccel_dev:  Pointer to virtio accel device.
 *
 * Function removes virtio accel device from the acceleration framework.
 * To be used by virtio accel device specific drivers.
 *
 * Return: void
 */
void virtaccel_devmgr_rm_dev(struct virtio_accel *vaccel_dev)
{
	mutex_lock(&table_lock);
	list_del(&vaccel_dev->list);
	num_devices--;
	mutex_unlock(&table_lock);
}

/*
 * virtaccel_devmgr_get_first()
 *
 * Function returns the first virtio accel device from the acceleration
 * framework.
 *
 * To be used by virtio accel device specific drivers.
 *
 * Return: pointer to vaccel_dev or NULL if not found.
 */
struct virtio_accel *virtaccel_devmgr_get_first(void)
{
	struct virtio_accel *dev = NULL;

	mutex_lock(&table_lock);
	if (!list_empty(&virtaccel_table))
		dev = list_first_entry(&virtaccel_table, struct virtio_accel,
				       list);
	mutex_unlock(&table_lock);
	return dev;
}

/*
 * virtaccel_dev_in_use() - Check whether vaccel_dev is currently in use
 * @vaccel_dev: Pointer to virtio accel device.
 *
 * To be used by virtio accel device specific drivers.
 *
 * Return: 1 when device is in use, 0 otherwise.
 */
int virtaccel_dev_in_use(struct virtio_accel *vaccel_dev)
{
	return atomic_read(&vaccel_dev->ref_count) != 0;
}

/*
 * virtaccel_dev_get() - Increment vaccel_dev reference count
 * @vaccel_dev: Pointer to virtio accel device.
 *
 * Increment the vaccel_dev refcount and if this is the first time
 * incrementing it during this period the vaccel_dev is in use,
 * increment the module refcount too.
 * To be used by virtio accel device specific drivers.
 *
 * Return: 0 when successful, EFAULT when fail to bump module refcount
 */
int virtaccel_dev_get(struct virtio_accel *vaccel_dev)
{
	if (atomic_add_return(1, &vaccel_dev->ref_count) == 1)
		if (!try_module_get(vaccel_dev->owner))
			return -EFAULT;
	return 0;
}

/*
 * virtaccel_dev_put() - Decrement vaccel_dev reference count
 * @vaccel_dev: Pointer to virtio accel device.
 *
 * Decrement the vaccel_dev refcount and if this is the last time
 * decrementing it during this period the vaccel_dev is in use,
 * decrement the module refcount too.
 * To be used by virtio accel device specific drivers.
 *
 * Return: void
 */
void virtaccel_dev_put(struct virtio_accel *vaccel_dev)
{
	if (atomic_sub_return(1, &vaccel_dev->ref_count) == 0)
		module_put(vaccel_dev->owner);
}

/*
 * virtaccel_dev_started() - Check whether device has started
 * @vaccel_dev: Pointer to virtio accel device.
 *
 * To be used by virtio accel device specific drivers.
 *
 * Return: 1 when the device has started, 0 otherwise
 */
int virtaccel_dev_started(struct virtio_accel *vaccel_dev)
{
	return (vaccel_dev->status & VIRTIO_ACCEL_S_HW_READY);
}

/*
 * virtaccel_get_dev_node() - Get vaccel_dev on the node.
 * @node:  Node id the driver works.
 *
 * Function returns the virtio accel device used fewest on the node.
 *
 * To be used by virtio accel device specific drivers.
 *
 * Return: pointer to vaccel_dev or NULL if not found.
 */
struct virtio_accel *virtaccel_get_dev_node(int node)
{
	struct virtio_accel *vaccel_dev = NULL;
	struct virtio_accel *tmp_dev;
	unsigned long best = ~0;
	unsigned long ctr;

	mutex_lock(&table_lock);
	list_for_each_entry(tmp_dev, virtaccel_devmgr_get_head(), list)
	{
		if ((node == dev_to_node(&tmp_dev->vdev->dev) ||
		     dev_to_node(&tmp_dev->vdev->dev) < 0) &&
		    virtaccel_dev_started(tmp_dev)) {
			ctr = atomic_read(&tmp_dev->ref_count);
			if (best > ctr) {
				vaccel_dev = tmp_dev;
				best = ctr;
			}
		}
	}

	if (!vaccel_dev) {
		pr_info("virtio_accel: Could not find a device on node %d\n",
			node);
		/* Get any started device */
		list_for_each_entry(tmp_dev, virtaccel_devmgr_get_head(), list)
		{
			if (virtaccel_dev_started(tmp_dev)) {
				vaccel_dev = tmp_dev;
				break;
			}
		}
	}
	mutex_unlock(&table_lock);
	if (!vaccel_dev)
		return NULL;

	virtaccel_dev_get(vaccel_dev);
	return vaccel_dev;
}

/*
 * virtaccel_dev_start() - Start virtio accel device
 * @vaccel:    Pointer to virtio accel device.
 *
 * Function notifies all the registered services that the virtio accel device
 * is ready to be used.
 * To be used by virtio accel device specific drivers.
 *
 * Return: 0 on success, EFAULT when fail to register algorithms
 */
int virtaccel_dev_start(struct virtio_accel *vaccel)
{
	return 0;
}

/*
 * virtaccel_dev_stop() - Stop virtio accel device
 * @vaccel:    Pointer to virtio accel device.
 *
 * Function notifies all the registered services that the virtio accel device
 * is ready to be used.
 * To be used by virtio accel device specific drivers.
 *
 * Return: void
 */
void virtaccel_dev_stop(struct virtio_accel *vaccel)
{
}
