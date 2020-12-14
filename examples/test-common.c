/*  Simple benchmark test for virtio-accel
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <getopt.h>

#include "accel.h"
#include "virtio_accel.h"
#include <vaccel_runtime.h>

static double udifftimespec(struct timespec start, struct timespec end)
{
	return (double)(end.tv_nsec - start.tv_nsec) +
		(double)(end.tv_sec - start.tv_sec) * 1000 * 1000 * 1000;
}

off_t file_to_buf(char *filename, char **buf)
{
	int fd, ret = 0;
	struct stat file;
	off_t fsize;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open(file)");
		return -2;
	}
	fstat(fd, &file);
	fsize = file.st_size;
	fprintf(stderr, "Filesize: %lu\n", fsize);

	*buf = malloc(fsize);
	if (!*buf) {
		fprintf(stderr, "malloc buf error\n");
		close(fd);
		return -2;
	}
	while (ret < fsize) {
		ret = read(fd, *buf, fsize);
		if (ret == 0)
			break;
		if (ret == -1) {
			fprintf(stderr, "read buf error\n");
			close(fd);
			return ret;
		}
	}
	close(fd);

	return fsize;
}

int parse_args(int argc, char** argv, int *iterations, char **filename, int *chunksize, int *verify)
{
	int o;

	if (iterations != NULL)
		*iterations = 1;
	if (verify != NULL)
		*verify = 0;

	while ((o = getopt (argc, argv, "i:f:c:v")) != -1) {
		switch (o) {
			case 'i':
				if (iterations != NULL)
					*iterations = atoi(optarg);
				break;
			case 'f':
				if (filename != NULL)
					*filename = optarg;
				break;
			case 'c':
				if (chunksize != NULL)
					*chunksize = atoi(optarg);
				break;
			case 'v':
				if (verify != NULL)
					*verify = 1;
				break;
			case 'h':
				// fall through
			default:
				fprintf(stderr, "Usage: test_<name> [-f <filename>] [-i <iterations>] [-c <chunksize>] [-v]\n");
				return 1;
		}
	}

	return 0;
}

int session_create(int *fd, struct accel_session *sess, unsigned int sess_type)
{
	struct vaccelrt_hdr sess_hdr;
	struct accel_arg sess_outargs[2];

	*fd = open("/dev/accel", O_RDWR, 0);
	if (*fd < 0) {
		perror("open(/dev/accel)");
		return 1;
	}

	fprintf(stderr, "\nTesting:\n");
	sess_hdr.type = sess_type;
	sess_outargs[0].buf = (__u8 *)&sess_hdr;
	sess_outargs[0].len = sizeof(sess_hdr);

	memset(sess, 0, sizeof(*sess));
	sess->op.in_nr = 0;
	sess->op.out_nr = 1;
	sess->op.out = sess_outargs;
	sess->op.in = NULL;

	if (ioctl(*fd, VACCEL_SESS_CREATE, sess)) {
		perror("ioctl(VACCEL_SESS_CREATE)");
		return 1;
	}

	return 0;
}

int session_destroy(int fd, struct accel_session *sess)
{
	if (ioctl(fd, VACCEL_SESS_DESTROY, sess)) {
		perror("ioctl(VACCEL_SESS_DESTROY)");
		return 1;
	}
	
	close(fd);
	return 0;
}

int do_operation(int fd, struct accel_session *sess, struct accel_arg *in_args,
		struct accel_arg *out_args, int in_nr, int out_nr, int iterations)
{
	struct accel_op *op = &sess->op;
	int in_nr_time = (in_nr) ? in_nr + 1 : in_nr;
	struct accel_arg in_args_time[in_nr_time];
	struct vaccelrt_tmr timers[10], timers_total[10];
	struct timespec start, end, start1, end1;
	double total = 0, op_time[iterations-1];

	memset(timers, 0, sizeof(timers));
	memset(timers_total, 0, sizeof(timers_total));

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (int i = 0; i < iterations; i++) {
		memset(op, 0, sizeof(*op));
		if (in_nr) {
			for (int j = 0; j < in_nr; j++) {
				in_args_time[j].len = in_args[j].len;
				in_args_time[j].buf = in_args[j].buf;
			}
			in_args_time[in_nr].len = sizeof(timers);
			in_args_time[in_nr].buf = (__u8 *)timers;
		}
		op->in_nr = in_nr_time;
		op->out_nr = out_nr;
		op->in = in_args_time;
		op->out = out_args;

		clock_gettime(CLOCK_MONOTONIC, &start1);
		if (ioctl(fd, VACCEL_DO_OP, sess)) {
			perror("ioctl(VACCEL_DO_OP)");
			return 1;
		}

		clock_gettime(CLOCK_MONOTONIC, &end1);
		for (int j = 0; j < 10; j++) {
			if (timers[j].time > 0) {
				if (i == 0)
					memcpy(timers_total[j].name, timers[j].name, sizeof(timers[j].name));
				timers_total[j].time += timers[j].time;
			}
		}

		op_time[i] = udifftimespec(start1, end1);
		total += op_time[i];
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	for (int i = 0; i < iterations; i++)
		printf("\top[%d]: %.6f ms\n", i, op_time[i] / 1000000.0);
	printf("\n");
	for (int i = 0; i < 10; i++)
		if (timers_total[i].time)
			printf("\t%s: %.6f ms\n", timers_total[i].name, timers_total[i].time / iterations);
	printf("\n\titerations: %d\n\top: %.6f ms\n", \
			iterations, total / (iterations * 1000000.0));
	printf ("\ttotal: %.6f secs\n", udifftimespec(start, end) / 1000000.0);

	return 0;
}
