// SPDX-License-Identifier: GPL-2.0

/*  Simple benchmark test for virtio-accel
 */
#include <arpa/inet.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test-common.h"
#include "accel.h"
#include <vaccel_runtime.h>

int verify_data(unsigned int k, unsigned int m, unsigned int n, const float *a,
		const float *b, float *c)
{
	float *c_v;
	size_t len_c = n * m * sizeof(*c);
	int ret = 0;

	if (!(c_v = malloc(len_c))) {
		perror("malloc()");
		return 1;
	}

	printf("Computing expected result...\n");
	for (int i = 0; i < m; i++) {
		for (int j = 0; j < n; j++) {
			float acc = 0.0F;
			for (int x = 0; x < k; x++) {
				acc += a[x * m + i] * b[j * k + x];
			}
			c_v[j * n + i] = acc;
		}
	}

	printf("Verifying...\n");
	for (int i = 0; i < m; i++) {
		for (int j = 0; j < n; j++) {
			if (fabsf(c[i * n + j] - c_v[i * n + j]) > 0.01) {
				ret = 1;
				printf("Mismatch in (%d,%d): %f vs %f\n", i, j,
				       c[i * n + j], c_v[i * n + j]);
			}
		}
	}

	return ret;
}

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
	int verify;
	unsigned int k;
	unsigned int m;
	unsigned int n;
	float *a;
	float *b;
	float *c;
	size_t len_a;
	size_t len_b;
	size_t len_c;

	ret = parse_args(argc, argv, &iterations, NULL, &chunksize, &verify);
	if (ret)
		return ret;

	ret = session_create(&fd, &sess, VACCELRT_SESS_GEMM);
	if (ret)
		return ret;

	k = m = n = chunksize;
	len_a = k * m * sizeof(*a);
	len_b = n * k * sizeof(*b);
	len_c = n * m * sizeof(*c);

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

	printf("Working with %dx%d arrays (%lubytes):\n", chunksize, chunksize,
	       len_a);

	for (int i = 0; i < k * m; i++) {
		a[i] = (float)rand() / (float)RAND_MAX;
	}
	for (int i = 0; i < n * k; i++) {
		b[i] = (float)rand() / (float)RAND_MAX;
	}
	memset(c, 0, len_c);

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	memset(op_args, 0, sizeof(op_args));
	sess_hdr.u.mul.k = htonl(k);
	sess_hdr.u.mul.m = htonl(m);
	sess_hdr.u.mul.n = htonl(n);
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = (__u8 *)&sess_hdr;
	op_args[1].len = len_a;
	op_args[1].buf = (__u8 *)a;
	op_args[2].len = len_b;
	op_args[2].buf = (__u8 *)b;
	op_args[3].len = len_c;
	op_args[3].buf = (__u8 *)c;

	ret = do_operation(fd, &sess, &op_args[3], &op_args[0], 1, 3,
			   iterations);
	if (ret)
		goto out;

	if (verify && (verify_data(k, m, n, a, b, c) == 0))
		printf("Success\n");
out:
	free(a);
	free(b);
	free(c);

	r = session_destroy(fd, &sess);
	if (r)
		return r;

	return ret;
}
