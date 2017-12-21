#ifndef _VIRTIO_ACCEL_H
#define _VIRTIO_ACCEL_H

#include <linux/types.h>
#include <linux/virtio_types.h>

#define VIRTIO_ID_ACCEL 21

#define VIRTIO_ACCEL_S_HW_READY  (1 << 0)

/* status */
#define VIRTIO_ACCEL_OK        0
#define VIRTIO_ACCEL_ERR       1
#define VIRTIO_ACCEL_BADMSG    2
#define VIRTIO_ACCEL_NOTSUPP   3
#define VIRTIO_ACCEL_INVSESS   4 /* Invalid session id */

struct virtio_accel_crypto_sess {
#define VIRTIO_ACCEL_C_NO_CIPHER      0
#define VIRTIO_ACCEL_C_CIPHER_AES_ECB 1
#define VIRTIO_ACCEL_C_CIPHER_AES_CBC 2
#define VIRTIO_ACCEL_C_CIPHER_AES_CTR 3
#define VIRTIO_ACCEL_C_CIPHER_AES_XTS 4
	__virtio32 cipher;
	__virtio32 keylen;
	__u8 *key;
	__u8 padding[7];
};

struct virtio_accel_crypto_op {
	__virtio32 src_len;
	__virtio32 dst_len;
	__virtio32 iv_len;
	__u8 *src;
	__u8 *dst;
	__u8 *iv;
	__u8 padding;
};

struct virtio_accel_gen_op {
	__virtio32 in_nr;
	__virtio32 out_nr;
	__virtio32 in_size;
	__virtio32 out_size;
	__u8 *in;
	__u8 *out;
	__u8 padding[6];
};

struct virtio_accel_hdr {
	__virtio32 session_id;

#define VIRTIO_ACCEL_NO_OP                        0
#define VIRTIO_ACCEL_G_OP_CREATE_SESSION          1
#define VIRTIO_ACCEL_G_OP_DESTROY_SESSION         2
#define VIRTIO_ACCEL_G_OP_DO_OP                   3
#define VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION   4
#define VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION  5
#define VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT          6
#define VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT          7
#define VIRTIO_ACCEL_C_OP_HASH_CREATE_SESSION     8
#define VIRTIO_ACCEL_C_OP_MAC_CREATE_SESSION      9
#define VIRTIO_ACCEL_C_OP_AEAD_CREATE_SESSION    10
#define VIRTIO_ACCEL_C_OP_HASH_DESTROY_SESSION   11
#define VIRTIO_ACCEL_C_OP_MAC_DESTROY_SESSION    12
#define VIRTIO_ACCEL_C_OP_AEAD_DESTROY_SESSION   13
#define VIRTIO_ACCEL_C_OP_HASH                   14
#define VIRTIO_ACCEL_C_OP_MAC                    15
#define VIRTIO_ACCEL_C_OP_AEAD_ENCRYPT           16
#define VIRTIO_ACCEL_C_OP_AEAD_DECRYPT           17
	__virtio32 op;
	/* session create structs */
	union {
		struct virtio_accel_crypto_sess crypto_sess;
		struct virtio_accel_crypto_op crypto_op;
		struct virtio_accel_gen_op gen_op;
	} u;
};

struct virtio_accel_crypto_conf {
    /* Maximum length of cipher key */
    __u32 max_cipher_key_len;
    /* Maximum length of authenticated key */
    __u32 max_auth_key_len;
};

struct virtio_accel_conf {
	__u32 status;
    /* Supported service mask */
    __u32 services;
    /* Maximum size of each crypto request's content */
    __u64 max_size;

    union {
        struct virtio_accel_crypto_conf crypto;
    } u;
};

#endif /* _VIRTIO_ACCEL_H */
