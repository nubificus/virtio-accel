#ifndef _ACCEL_H
#define _ACCEL_H

#include <linux/types.h>
#ifndef __KERNEL__
#define __user
#endif

/* IOCTLs */
#define ACCIOC_GEN_SESS_CREATE      _IOWR('@', 0, struct accel_session)
#define ACCIOC_GEN_SESS_DESTROY     _IOWR('@', 1, struct accel_session)
#define ACCIOC_GEN_DO_OP            _IOWR('@', 2, struct accel_op)
#define ACCIOC_CRYPTO_SESS_CREATE   _IOWR('@', 3, struct accel_session)
#define ACCIOC_CRYPTO_SESS_DESTROY  _IOR('@', 4, struct accel_session)
#define ACCIOC_CRYPTO_ENCRYPT       _IOWR('@', 5, struct accel_op)
#define ACCIOC_CRYPTO_DECRYPT       _IOWR('@', 6, struct accel_op)


struct accel_crypto_sess {
	__u32 cipher;
	__u32 keylen;
	__u8 __user *key;
};

struct accel_gen_op_arg {
	__u32 len;
	__u8 *buf;
};

struct accel_gen_op {
	__u32 in_nr;
	__u32 out_nr;
	struct accel_gen_op_arg __user *in;
	struct accel_gen_op_arg __user *out;
};

struct accel_session {
	__u32 id;
	union {
		struct accel_crypto_sess crypto;
		struct accel_gen_op gen;
	} u;
};

struct accel_crypto_op {
	__u32 src_len;
	__u32 dst_len;
	__u32 iv_len;
	__u8 __user *src;
	__u8 __user *dst;
	__u8 __user *iv;
};

struct accel_op {
	__u32 session_id;
	union {
		struct accel_crypto_op crypto;
		struct accel_gen_op gen;
	} u;
};


int accel_dev_init(void);
void accel_dev_destroy(void);

#endif /* _ACCEL_H */
