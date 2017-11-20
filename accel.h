#ifndef _ACCEL_H
#define _ACCEL_H

struct accel_crypto_op {
	__u32 cipher;
	__u32 keylen;
	__u32 __user *key;
}

struct accel_session {
	__u32 op;
	__u32 id;
	union {
		struct accel_crypto_op crypto_op;
	} u;
}

#endif /* _ACCEL_H */
