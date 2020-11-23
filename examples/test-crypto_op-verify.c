/*  cryptodev_test - simple benchmark tool for cryptodev
 *
 *    Copyright (C) 2010 by Phil Sutter <phil.sutter@viprinet.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>

#include "accel.h"
#include "virtio_accel.h"
#include <vaccel_runtime.h>

#define MAX(x,y) ((x)>(y)?(x):(y))

int test_data(struct accel_session *sess, int fdc, int chunksize)
{
	struct accel_op *op = &sess->op;
	struct vaccelrt_hdr sess_hdr;
	struct accel_arg op_args[3];
	char *buffer, *buffer_dec, *buffer_enc, iv[32];
	
	if (!(buffer = malloc(chunksize))) {
		perror("malloc()");
		return 1;
	}
	if (!(buffer_enc = malloc(chunksize))) {
		perror("malloc()");
		return 1;
	}
	if (!(buffer_dec = malloc(chunksize))) {
		perror("malloc()");
		return 1;
	}
	//memset(iv, 0x23, 32);

	printf("Encrypting in chunks of %d bytes:\n", chunksize);
	fflush(stdout);

	memset(buffer, 'a', chunksize-1);
	memset(buffer+chunksize, '\0', 1);

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	sess_hdr.u.aes.op = VACCELRT_AES_ENCRYPT;
	memset(op, 0, sizeof(*op));
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = &sess_hdr;
	op_args[1].len = chunksize;
	op_args[1].buf = (__u8 *)buffer;
	op_args[2].len = chunksize;
	op_args[2].buf = (__u8 *)buffer_enc;
	op->in_nr = 1;
	op->out_nr = 2;
	op->out = &op_args[0];
	op->in = &op_args[2];

	if (ioctl(fdc, VACCEL_DO_OP, sess)) {
		perror("ioctl(VACCEL_DO_OP)");
		return 1;
	}

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	sess_hdr.u.aes.op = VACCELRT_AES_DECRYPT;
	memset(op, 0, sizeof(*op));
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = &sess_hdr;
	op_args[1].len = chunksize;
	op_args[1].buf = (__u8 *)buffer_enc;
	op_args[2].len = chunksize;
	op_args[2].buf = (__u8 *)buffer_dec;
	op->in_nr = 1;
	op->out_nr = 2;
	op->out = &op_args[0];
	op->in = &op_args[2];

	if (ioctl(fdc, VACCEL_DO_OP, sess)) {
		perror("ioctl(VACCEL_DO_OP)");
		return 1;
	}

	if (strcmp(buffer, buffer_dec) != 0) {
		printf("Failure\n");
		return 1;
	}

	printf("Success\n");

	free(buffer);
	free(buffer_enc);
	free(buffer_dec);
	return 0;
}

int main(int argc, char** argv)
{
	int fd;
	struct accel_session sess;
	struct accel_op *op = &sess.op;
	struct vaccelrt_hdr sess_hdr;
	struct accel_arg sess_outargs[2];
	char keybuf[32];
	size_t keylen;

	if ((fd = open("/dev/accel", O_RDWR, 0)) < 0) {
		perror("open()");
		return 1;
	}
	
	fprintf(stderr, "\nTesting:\n");
	sess_hdr.type = VACCELRT_SESS_AES_ECB;
	sess_outargs[0].buf = (__u8 *)&sess_hdr;
	sess_outargs[0].len = sizeof(struct vaccelrt_hdr);

	memset(&sess, 0, sizeof(sess));	
	sess.op.in_nr = 0;
	sess.op.out_nr = 1;
	sess.op.out = sess_outargs;
	sess.op.in = NULL;

	if (ioctl(fd, VACCEL_SESS_CREATE, &sess)) {
		perror("ioctl(VACCEL_SESS_CREATE)");
		return 1;
	}

	keylen = 16;
	memset(keybuf, 0x42, keylen);

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	memset(op, 0, sizeof(*op));
	sess_hdr.u.aes.op = VACCELRT_AES_SET_KEY;
	sess_outargs[0].buf = (__u8 *)&sess_hdr;
	sess_outargs[0].len = sizeof(struct vaccelrt_hdr);
	sess_outargs[1].buf = (__u8 *)keybuf;
	sess_outargs[1].len = keylen;
	op->in_nr = 0;
	op->out_nr = 2;
	op->out = &sess_outargs[0];
	op->in = NULL;

	if (ioctl(fd, VACCEL_DO_OP, &sess)) {
		perror("ioctl(VACCEL_DO_OP)");
		return 1;
	}

	test_data(&sess, fd, 1024);

	if (ioctl(fd, VACCEL_SESS_DESTROY, &sess)) {
		perror("ioctl(VACCEL_SESS_DESTROY)");
		return 1;
	}

	close(fd);
	return 0;
}
