#ifndef _ACCEL_H
#define _ACCEL_H

struct accel_crypto_sess {
	__u32 cipher;
	__u32 keylen;
	__u32 __user *key;
}

struct accel_session {
	__u32 id;
	union {
		struct accel_crypto_sess crypto;
	} u;
}

struct accel_crypto_op {
	__u32 src_len;
	__u8 __user *src;
	__u8 __user *dst;
	__u32 iv_len;
	__u8 __user *iv;
}

struct accel_op {
	__u32 sess_id;
	union {
		struct accel_crypto_op crypto;
	} u;
}

#endif /* _ACCEL_H */
