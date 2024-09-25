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
	struct accel_arg op_args[3];
	struct vaccelrt_hdr sess_hdr;
	char *filename = "example.jpg";
	char *image = NULL;
	char out_imgname[512];
	off_t image_len;

	ret = parse_args(argc, argv, &iterations, &filename, NULL, NULL);
	if (ret)
		return ret;

	image_len = file_to_buf(filename, &image);
	if (image_len < 0)
		return 1;

	ret = session_create(&fd, &sess, VACCELRT_SESS_DETECT);
	if (ret)
		return ret;

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	memset(op_args, 0, sizeof(op_args));
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = (__u8 *)&sess_hdr;
	op_args[1].len = image_len;
	op_args[1].buf = (__u8 *)image;
	op_args[2].len = sizeof(out_imgname);
	op_args[2].buf = (__u8 *)out_imgname;

	ret = do_operation(fd, &sess, &op_args[2], &op_args[0], 1, 2,
			   iterations);
	if (ret)
		goto out;

	if (iterations == 1) {
		printf("output image name: %s\n", out_imgname);
	}

out:
	r = session_destroy(fd, &sess);
	if (r)
		return r;

	return ret;
}
