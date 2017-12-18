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

#define MAX(x,y) ((x)>(y)?(x):(y))

int test_data(struct accel_session *sess, int fdc, int chunksize)
{
	struct accel_op op;
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

	memset(&op, 0, sizeof(op));
	op.session_id = sess->id;
	op.u.crypto.src_len = chunksize;
	op.u.crypto.dst_len = op.u.crypto.src_len;
	//cop.iv = (unsigned char *)iv;
	op.u.crypto.src = (unsigned char *)buffer;
	op.u.crypto.dst = (unsigned char *)buffer_enc;

	if (ioctl(fdc, ACCIOC_CRYPTO_ENCRYPT, &op)) {
		perror("ioctl(ACCIOC_CRYPTO_ENCRYPT)");
		return 1;
	}
	
	op.u.crypto.src = (unsigned char *)buffer_enc;
	op.u.crypto.dst = (unsigned char *)buffer_dec;
	if (ioctl(fdc, ACCIOC_CRYPTO_DECRYPT, &op)) {
		perror("ioctl(ACCIOC_CRYPTO_DECRYPT)");
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
	char keybuf[32];

	if ((fd = open("/dev/accel", O_RDWR, 0)) < 0) {
		perror("open()");
		return 1;
	}
	
	fprintf(stderr, "\nTesting cipher:\n");
	memset(&sess, 0, sizeof(sess));
	sess.u.crypto.cipher = VIRTIO_ACCEL_C_CIPHER_AES_ECB;
	sess.u.crypto.keylen = 16;
	memset(keybuf, 0x42, 16);
	sess.u.crypto.key = (unsigned char *)keybuf;
	if (ioctl(fd, ACCIOC_CRYPTO_SESS_CREATE, &sess)) {
		perror("ioctl(ACCIOC_CRYPTO_SESS_CREATE)");
		return 1;
	}
	
	test_data(&sess, fd, 1024);

	if (ioctl(fd, ACCIOC_CRYPTO_SESS_DESTROY, &sess)) {
		perror("ioctl(ACCIOC_CRYPTO_SESS_DESTROY)");
		return 1;
	}	

	close(fd);
	return 0;
}
