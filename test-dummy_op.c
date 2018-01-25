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

int process_data(struct accel_session *sess, int fdc, int chunksize)
{
	struct accel_op op;
	struct vaccelrt_hdr sess_hdr;
	struct accel_gen_op_arg op_args[2];
	char *buffer;
	static int val = 23;
	int tt = 0, ret;
	struct timeval start, end;
	struct timespec start1, end1;
	double total = 0, ttotal = 0;
	double secs, ddata, dspeed;
	char metric[16];

	if (!(buffer = malloc(chunksize))) {
		perror("malloc()");
		return 1;
	}

	printf("Working in chunks of %d bytes:\n", chunksize);
	fflush(stdout);

	memset(buffer, val++, chunksize);

	must_finish = 0;
//	alarm(5);

	gettimeofday(&start, NULL);
//	do {
		memset(&op, 0, sizeof(op));
		op.session_id = sess->id;
		op_args[0].len = sizeof(sess_hdr);
		op_args[0].buf = (__u8 *)&sess_hdr;
		op_args[1].len = chunksize;
		op_args[1].buf = (unsigned char *)buffer;
		op.u.gen.in_nr = 1;
		op.u.gen.out_nr = 1;
		op.u.gen.in = &op_args[1];
		op.u.gen.out = &op_args[0];

	clock_gettime(CLOCK_MONOTONIC, &start1);
		if (ret = ioctl(fdc, ACCIOC_GEN_DO_OP, &op)) {
			perror("ioctl(ACCIOC_GEN_DO_OP)");
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
	int fd, i;
	struct accel_session sess;
	struct vaccelrt_hdr sess_hdr;
	struct accel_gen_op_arg sess_outargs[1];

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
	
	fprintf(stderr, "\nTesting:\n");
	sess_hdr.type = VACCELRT_SESS_NONE;
	sess_outargs[0].buf = (__u8 *)&sess_hdr;
	sess_outargs[0].len = sizeof(struct vaccelrt_hdr);

	memset(&sess, 0, sizeof(sess));
	sess.u.gen.in_nr = 0;
	sess.u.gen.out_nr = 1;
	sess.u.gen.out = sess_outargs;
	sess.u.gen.in = NULL;

	if (ioctl(fd, ACCIOC_GEN_SESS_CREATE, &sess)) {
		perror("ioctl(ACCIOC_GEN_SESS_CREATE)");
		return 1;
	}
	
	for (i = 512; i <= (512); i *= 2) {
		if (process_data(&sess, fd, i))
			break;
	}

	if (ioctl(fd, ACCIOC_GEN_SESS_DESTROY, &sess)) {
		perror("ioctl(ACCIOC_GEN_SESS_DESTROY)");
		return 1;
	}
	
	close(fd);
	return 0;
}
