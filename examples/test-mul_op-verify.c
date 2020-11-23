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
#include <math.h>
#include <arpa/inet.h>

#include "accel.h"
#include "virtio_accel.h"
#include <vaccel_runtime.h>

static volatile int must_finish;

static void alarm_handler(int signo)
{
        must_finish = 1;
}

int verify_data(unsigned int k, unsigned int m, unsigned int n, float *a,
			float *b, float *c)
{
	float *c_v;
	size_t len_a, len_b, len_c;
	int ret = 0;

	len_a = k * m  * sizeof(*a);
	len_b = n * k  * sizeof(*b);
	len_c = n * m  * sizeof(*c);
	
	if (!(c_v = malloc(len_c))) {
		perror("malloc()");
		return 1;
	}

	printf("Computing expected result...\n");
	for (int i = 0; i < m; i++) {
		for (int j = 0; j < n; j++) {
			float acc = 0.0f;
			for (int x = 0; x < k; x++) {
				acc += a[x*m + i] * b[j*k + x];
			}
			c_v[j*n + i] = acc;
		}
	}

	printf("Verifying...\n");
	for (int i = 0; i < m; i++) {
		for (int j = 0; j < n; j++) {
			if (fabs(c[i*n + j] - c_v[i*n + j]) > 0.01) {
				ret = 1;
				printf("Mismatch in (%d,%d): %f vs %f\n", i, j, c[i*n + j],
						c_v[i*n + j]);
			}
		}
	}

	return ret;
}

int process_data(struct accel_session *sess, int fdc, int chunksize)
{
	struct accel_op *op = &sess->op;
	struct vaccelrt_hdr sess_hdr;
	struct accel_arg op_args[4];
	float *a, *b, *c;
	int ret;
	unsigned int k, m, n;
	size_t len_a, len_b, len_c;

	k = m = n = chunksize;
	len_a = k * m  * sizeof(*a);
	len_b = n * k  * sizeof(*b);
	len_c = n * m  * sizeof(*c);
	printf("k=%u,m=%u,n=%u len_a=%lu,len_b=%lu,len_c=%lu\n",
		k, m, n, len_a, len_b, len_c);
	
	// Matrices in column-major format
	// A: K columns, M rows
	// B: N columns, K rows
	// C: N columns, M rows
	if (!(a = malloc(len_a))) {
		perror("malloc()");
		return 1;
	}
	if (!(b = malloc(len_b))) {
		perror("malloc()");
		return 1;
	}
	if (!(c = malloc(len_c))) {
		perror("malloc()");
		return 1;
	}

	printf("Trying %d bytes:\n", chunksize);
	fflush(stdout);

	for (int i = 0; i < k * m; i++) {
		a[i] = (float)rand() / (float)RAND_MAX;
	}
	for (int i = 0; i < n * k; i++) {
		b[i] = (float)rand() / (float)RAND_MAX;
	}
	memset(c, 0, len_c);

	must_finish = 0;
//	alarm(2);
	
//	do {
		printf("Processing data...\n");
		memset(&sess_hdr, 0, sizeof(sess_hdr));
		sess_hdr.u.mul.k = htonl(k);
		sess_hdr.u.mul.m = htonl(m);
		sess_hdr.u.mul.n = htonl(n);
		memset(op, 0, sizeof(*op));
		op_args[0].len = sizeof(sess_hdr);
		op_args[0].buf = (__u8 *)&sess_hdr;
		op_args[1].len = len_a;
		op_args[1].buf = (unsigned char *)a;
		op_args[2].len = len_b;
		op_args[2].buf = (unsigned char *)b;
		op_args[3].len = len_c;
		op_args[3].buf = (unsigned char *)c;
		op->in_nr = 1;
		op->out_nr = 3;
		op->in = &op_args[3];
		op->out = &op_args[0];

		if (ret = ioctl(fdc, VACCEL_DO_OP, sess)) {
			perror("ioctl(VACCEL_DO_OP)");
			printf("%d\n", ret);
			return 1;
		}

		if (verify_data(k, m, n, a, b, c) == 0)
			printf("Success\n");
//	} while(must_finish==0);

	free(a);
	free(b);
	free(c);
	return 0;
}

int main(int argc, char** argv)
{
	int fd;
	struct accel_session sess;
	struct vaccelrt_hdr sess_hdr;
	struct accel_arg sess_outargs[1];

	signal(SIGALRM, alarm_handler);
	
	if ((fd = open("/dev/accel", O_RDWR, 0)) < 0) {
		perror("open()");
		return 1;
	}
	
	fprintf(stderr, "\nTesting:\n");
	sess_hdr.type = VACCELRT_SESS_GEMM;
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
	
	process_data(&sess, fd, 1024);
	
	if (ioctl(fd, VACCEL_SESS_DESTROY, &sess)) {
		perror("ioctl(VACCEL_SESS_DESTROY)");
		return 1;
	}
	
	close(fd);
	return 0;
}
