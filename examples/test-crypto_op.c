/*  Simple benchmark test for virtio-accel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include "test-common.h"
#include "accel.h"
#include <vaccel_runtime.h>

int verify_data(struct accel_session *sess, int fd, int chunksize, char *buf,
		char *buf_enc)
{
	int ret, i;
	struct accel_arg op_args[3];
	struct vaccelrt_hdr sess_hdr;
	char *buf_dec;
	
	buf_dec = malloc(chunksize);
	if (!buf_dec) {
		perror("malloc(buf_dec)");
		return 1;
	}

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	memset(op_args, 0, sizeof(op_args));
	sess_hdr.u.aes.op = VACCELRT_AES_DECRYPT;
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = (__u8 *)&sess_hdr;
	op_args[1].len = chunksize;
	op_args[1].buf = (__u8 *)buf_enc;
	op_args[2].len = chunksize;
	op_args[2].buf = (__u8 *)buf_dec;
	ret = do_operation(fd, sess, &op_args[2], &op_args[0], 1, 2, 1);
	if (ret)
		goto out;

	for (i = 0; i < chunksize; i++) {
		if (strcmp(&buf[i], &buf_dec[i]) == 0) {
			printf("Mismatch in (%d): %c vs %c\n", i, 
					buf[i], buf_dec[i]);
			ret = 1;
			goto out;
		}
	}

out:
	free(buf_dec);
	return ret;
}

int main(int argc, char** argv)
{
	int fd, ret = 0, r = 0, iterations;
	struct accel_session sess;
	struct accel_arg op_args[3];
	struct vaccelrt_hdr sess_hdr;
	int chunksize = 64;
	char *buf = NULL, *buf_enc = NULL;
	char keybuf[16];
	size_t keylen;
	int verify;

	ret = parse_args(argc, argv, &iterations, NULL, &chunksize, &verify);
	if (ret)
		return ret;

	ret = session_create(&fd, &sess, VACCELRT_SESS_AES_ECB);
	if (ret)
		return ret;

	keylen = 16;
	memset(keybuf, 0x42, keylen);

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	memset(op_args, 0, sizeof(op_args));
	sess_hdr.u.aes.op = VACCELRT_AES_SET_KEY;
	op_args[0].len = sizeof(struct vaccelrt_hdr);
	op_args[0].buf = (__u8 *)&sess_hdr;
	op_args[1].len = keylen;
	op_args[1].buf = (__u8 *)keybuf;
	ret = do_operation(fd, &sess, NULL, &op_args[0], 0, 2, 1);
	if (ret)
		goto out_sess;

	buf = malloc(chunksize);
	if (!buf) {
		perror("malloc(buf)");
		ret = 1;
		goto out_sess;
	}
	memset(buf, 'a', chunksize);

	buf_enc = malloc(chunksize);
	if (!buf_enc) {
		perror("malloc(buf_enc)");
		ret = 1;
		goto out_sess;
	}
	memset(buf_enc, 0, chunksize);

	printf("Working in chunks of %d bytes:\n", chunksize);

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	memset(op_args, 0, sizeof(op_args));
	sess_hdr.u.aes.op = VACCELRT_AES_ENCRYPT;
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = (__u8 *)&sess_hdr;
	op_args[1].len = chunksize;
	op_args[1].buf = (__u8 *)buf;
	op_args[2].len = chunksize;
	op_args[2].buf = (__u8 *)buf_enc;

	ret = do_operation(fd, &sess, &op_args[2], &op_args[0], 1, 2, iterations);
	if (ret)
		goto out;

	if (verify && (verify_data(&sess, fd, chunksize, buf, buf_enc) == 0))
		printf("Success\n");

out:
	free(buf);
out_sess:
	r = session_destroy(fd, &sess);
	if (r)
		return r;

	return ret;
}
