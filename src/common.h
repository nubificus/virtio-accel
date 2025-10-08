// SPDX-License-Identifier: GPL-2.0

#ifndef _VIRTIO_ACCEL_COMMON_H
#define _VIRTIO_ACCEL_COMMON_H

#include <linux/version.h>

#ifndef fallthrough
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough \
	do {        \
	} while (0) /* fallthrough */
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define kfree_sensitive kzfree;
#endif

#define vacl_err(fmt, ...) pr_err("virtio-accel: " fmt, ##__VA_ARGS__)
#define vacl_warn(fmt, ...) pr_warn("virtio-accel: " fmt, ##__VA_ARGS__)
#define vacl_info(fmt, ...) pr_info("virtio-accel: " fmt, ##__VA_ARGS__)
#define vacl_debug(fmt, ...) pr_debug("virtio-accel: " fmt, ##__VA_ARGS__)

#endif /* _VIRTIO_ACCEL_COMMON_H */
