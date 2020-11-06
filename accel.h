#ifndef _ACCEL_H
#define _ACCEL_H

#include <linux/types.h>
#ifndef __KERNEL__
#define __user
#endif

/* IOCTLs */
#define VACCEL_SESS_CREATE      _IOWR('@', 0, struct accel_session)
#define VACCEL_SESS_DESTROY     _IOWR('@', 1, struct accel_session)
#define VACCEL_DO_OP            _IOWR('@', 2, struct accel_session)


struct accel_arg {
	__u32 len;
	__u8 __user *buf;
};

struct accel_op {
	/* number of in arguments */
	__u32 in_nr;

	/* pointer to in arguments */
	struct accel_arg __user *in;

	/* number of out arguments */
	__u32 out_nr;

	/* pointer to out arguments */
	struct accel_arg __user *out;
};

struct accel_session {
	/* Session id */
	__u32 id;

	/* operation performed currently */
	struct accel_op op;
};

int accel_dev_init(void);
void accel_dev_destroy(void);

#endif /* _ACCEL_H */
