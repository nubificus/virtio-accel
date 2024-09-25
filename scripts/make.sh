#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -e

MAKE_BIN=$1
SRC_DIR=$2
OUTPUT_DIR=$3
OUTPUT=$4
shift 4

for a in "$@"; do
	[ "$a" = "modules_install" ] && INSTALL=1 && break
done

[ "${OUTPUT_DIR}" = "${SRC_DIR}" ] && return

if [ -n "${MESON_INSTALL_DESTDIR_PREFIX}" ]; then
	set -- "$@" INSTALL_MOD_PATH="${MESON_INSTALL_DESTDIR_PREFIX}"
fi

"${MAKE_BIN}" -C "${SRC_DIR}" "$@"

if [ -z "$INSTALL" ]; then
	cp "${BUILD_DIR}"/"${OUTPUT}" "${OUTPUT_DIR}"/"${OUTPUT}"
fi
