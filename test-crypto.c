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

static int si = 1; /* SI by default */

static double udifftimeval(struct timeval start, struct timeval end)
{
	return (double)(end.tv_usec - start.tv_usec) +
	       (double)(end.tv_sec - start.tv_sec) * 1000 * 1000;
}

static double udifftimeval1(struct timespec start, struct timespec end)
{
	return (double)(end.tv_nsec - start.tv_nsec) +
	       (double)(end.tv_sec - start.tv_sec) * 1000 * 1000 * 1000;
}

static volatile int must_finish;

static void alarm_handler(int signo)
{
        must_finish = 1;
}

static char *units[] = { "", "Ki", "Mi", "Gi", "Ti", 0};
static char *si_units[] = { "", "K", "M", "G", "T", 0};

static void value2human(int si, double bytes, double time, double* data,
						double* speed,char* metric)
{
	int unit = 0;

	*data = bytes;
	
	if (si) {
		while (*data > 1000 && si_units[unit + 1]) {
			*data /= 1000;
			unit++;
		}
		*speed = *data / time;
		sprintf(metric, "%sB", si_units[unit]);
	} else {
		while (*data > 1024 && units[unit + 1]) {
			*data /= 1024;
			unit++;
		}
		*speed = *data / time;
		sprintf(metric, "%sB", units[unit]);
	}
}

#define MAX(x,y) ((x)>(y)?(x):(y))

int encrypt_data(struct accel_session *sess, int fdc, int chunksize)
{
	struct accel_op op;
	char *buffer, iv[32];
	static int val = 23;
	int tt = 0, ret;
	struct timeval start, end;
	struct timespec start1, end1;
	double total = 0, ttotal = 0;
	double secs, ddata, dspeed;
	char metric[16];
/*
	if (alignmask) {
		if (posix_memalign((void **)&buffer, MAX(alignmask + 1, sizeof(void*)),
							chunksize)) {
			printf("posix_memalign() failed! (mask %x, size: %d)\n",
					alignmask+1, chunksize);
			return 1;
		}
	} else {
		if (!(buffer = malloc(chunksize))) {
			perror("malloc()");
			return 1;
		}
	}
*/
	if (!(buffer = malloc(chunksize))) {
		perror("malloc()");
		return 1;
	}
	memset(iv, 0x23, 32);

	printf("Encrypting in chunks of %d bytes:\n", chunksize);
	fflush(stdout);

	memset(buffer, val++, chunksize);

	must_finish = 0;
//	alarm(5);

	gettimeofday(&start, NULL);
//	do {
		memset(&op, 0, sizeof(op));
		op.session_id = sess->id;
		op.u.crypto.src_len = chunksize;
		op.u.crypto.dst_len = op.u.crypto.src_len;
		//cop.iv = (unsigned char *)iv;
		op.u.crypto.src = op.u.crypto.dst = (unsigned char *)buffer;

	clock_gettime(CLOCK_MONOTONIC, &start1);
		if (ret = ioctl(fdc, ACCIOC_CRYPTO_ENCRYPT, &op)) {
			perror("ioctl(ACCIOC_CRYPTO_ENCRYPT)");
			printf("%d\n", ret);
			return 1;
		}
	clock_gettime(CLOCK_MONOTONIC, &end1);
	ttotal += udifftimeval1(start1, end1);
	tt++;

		total+=chunksize;
		//if (total > 128 * 1048576) {
		//	must_finish=1;
		//}
//	} while(must_finish==0);
	gettimeofday(&end, NULL);

	secs = udifftimeval(start, end)/ 1000000.0;

	value2human(si, total, secs, &ddata, &dspeed, metric);
	printf("\tioctl: %.6f ms, %d, %.6f s\n", ttotal / (tt * 1000000.0),
			tt, ttotal / 1000000000.0);
	printf ("\tdone. %.2f %s in %.2f secs: ", ddata, metric, secs);
	printf ("%.2f %s/sec\n", dspeed, metric);

	free(buffer);
	return 0;
}

int main(int argc, char** argv)
{
	int fd, i, fdc = -1, alignmask = 0;
	struct accel_session sess;
	char keybuf[32];

	signal(SIGALRM, alarm_handler);
	
	if (argc > 1) {
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
			printf("Usage: speed [--kib]\n");
			exit(0);
		}
		if (strcmp(argv[1], "--kib") == 0) {
			si = 0;
		}
	}

	if ((fd = open("/dev/accel", O_RDWR, 0)) < 0) {
		perror("open()");
		return 1;
	}
/*
	if (ioctl(fd, CRIOGET, &fdc)) {
		perror("ioctl(CRIOGET)");
		return 1;
	}

	fprintf(stderr, "Testing NULL cipher: \n");
	memset(&sess, 0, sizeof(sess));
	sess.cipher = CRYPTO_NULL;
	sess.keylen = 0;
	sess.key = (unsigned char *)keybuf;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}
#ifdef CIOCGSESSINFO
	siop.ses = sess.ses;
	if (ioctl(fdc, CIOCGSESSINFO, &siop)) {
		perror("ioctl(CIOCGSESSINFO)");
		return 1;
	}
	alignmask = siop.alignmask;
#endif

	for (i = 512; i <= (64 * 1024); i *= 2) {
		if (encrypt_data(&sess, fdc, i, alignmask))
			break;
	}
*/
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
	
	for (i = 512; i <= (512 * 1024); i *= 2) {
		if (encrypt_data(&sess, fd, i))
			break;
	}

	if (ioctl(fd, ACCIOC_CRYPTO_SESS_DESTROY, &sess)) {
		perror("ioctl(ACCIOC_CRYPTO_SESS_DESTROY)");
		return 1;
	}
	
	close(fd);
	return 0;
}
