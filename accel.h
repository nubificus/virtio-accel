// SPDX-License-Identifier: GPL-2.0

#ifndef _ACCEL_H
#define _ACCEL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#ifndef __KERNEL__
#define __user
#endif

#define TIMERS_NAME_MAX 64

/* IOCTLs */
#define ACCEL_SESS_CREATE _IOWR('@', 0, struct accel_op)
#define ACCEL_SESS_DESTROY _IOWR('@', 1, __u64)
#define ACCEL_DO_OP _IOWR('@', 2, struct accel_op)
#define ACCEL_GET_TIMERS _IOWR('@', 3, struct accel_op)

struct accel_arg {
	__u64 buf;
	__u32 len;
	__u32 type;
	__u32 custom_type_id;
};

struct accel_op {
	/* Session id */
	__u64 session_id;

	/* User-defined operation code */
	__u32 op_code;

	/* Number of out arguments */
	__u32 out_nr;

	/* Number of in arguments */
	__u32 in_nr;

	// FIXME: use __u64 for ptrs

	/* Pointer to out arguments */
	__u64 out;

	/* Pointer to in arguments */
	__u64 in;

	/* Operation return value */
	__u32 ret;
};

struct accel_prof_sample {
	/* Timestamp (nsec) of entering the region */
	__u64 start;

	/* Time (nsec) elapsed inside the region */
	__u64 time;
};

struct accel_prof_region {
	/* Name of the region */
	char name[TIMERS_NAME_MAX];

	/* Number of collected samples */
	__u64 nr_entries;

	/* Array of collected samples */
	struct accel_prof_sample *samples;

	/* Allocated size for the array */
	__u64 size;
};

int accel_dev_init(void);
void accel_dev_destroy(void);

#endif /* _ACCEL_H */
