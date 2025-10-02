// SPDX-License-Identifier: GPL-2.0

#ifndef _ACCEL_INTERNAL_H
#define _ACCEL_INTERNAL_H

#include "accel.h"

struct accel_op_req {
	struct accel_op u_op;
	struct accel_arg *out;
	struct accel_arg *in;
};

#endif /* _ACCEL_INTERNAL_H */
