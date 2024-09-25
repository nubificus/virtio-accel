// SPDX-License-Identifier: GPL-2.0

/*  Simple benchmark test for virtio-accel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test-common.h"
#include "accel.h"
#include <vaccel_runtime.h>

int main(int argc, char **argv)
{
	int fd;
	int ret = 0;
	int r = 0;
	int iterations;
	struct accel_session sess;
	struct accel_arg op_args[4];
	struct vaccelrt_hdr sess_hdr;
	int chunksize = 64;
	unsigned char *buffer = NULL;

	ret = parse_args(argc, argv, &iterations, NULL, &chunksize, NULL);
	if (ret)
		return ret;

	ret = session_create(&fd, &sess, VACCELRT_SESS_NONE);
	if (ret)
		return ret;

	buffer = malloc(chunksize);
	if (!buffer) {
		perror("malloc()");
		ret = 1;
		goto out;
	}
	memset(buffer, 1, chunksize);

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	memset(op_args, 0, sizeof(op_args));
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = (__u8 *)&sess_hdr;
	op_args[1].len = chunksize;
	op_args[1].buf = (__u8 *)buffer;

	ret = do_operation(fd, &sess, &op_args[1], &op_args[0], 1, 1,
			   iterations);

	free(buffer);
out:
	r = session_destroy(fd, &sess);
	if (r)
		return r;

	return ret;
}
