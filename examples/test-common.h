/*  Simple benchmark test for virtio-accel
 */
#ifndef _TEST_COMMON_H
#define _TEST_COMMON_H

#include <sys/time.h>
#include "accel.h"

off_t file_to_buf(char *filename, char **buf);

int parse_args(int argc, char** argv, int *iterations, char **filename, int *chunksize, int *verify);

int session_create(int *fd, struct accel_session *sess, unsigned int sess_type);

int session_destroy(int fd, struct accel_session *sess);

int do_operation(int fd, struct accel_session *sess, struct accel_arg *in_args,
		struct accel_arg *out_args, int in_nr, int out_nr, int iterations);

#endif /* _TEST_COMMON_H */
