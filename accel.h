#ifndef _ACCEL_H
#define _ACCEL_H

#include <linux/types.h>
#ifndef __KERNEL__
#define __user
#endif

#define TIMERS_NAME_MAX 64

/* IOCTLs */
#define VACCEL_SESS_CREATE      _IOWR('@', 0, struct accel_session)
#define VACCEL_SESS_DESTROY     _IOWR('@', 1, struct accel_session)
#define VACCEL_DO_OP            _IOWR('@', 2, struct accel_session)
#define VACCEL_GET_TIMERS       _IOWR('@', 3, struct accel_session)


struct accel_arg {
	__u32 len;
	__u8 __user *buf;
};

struct accel_op {
	/* Number of in arguments */
	__u32 in_nr;

	/* Pointer to in arguments */
	struct accel_arg __user *in;

	/* Number of out arguments */
	__u32 out_nr;

	/* Pointer to out arguments */
	struct accel_arg __user *out;
};

struct accel_session {
	/* Session id */
	__u32 id;

	/* Operation performed currently */
	struct accel_op op;
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
