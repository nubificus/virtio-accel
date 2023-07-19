#!/bin/sh

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

${MAKE_BIN} -C "${SRC_DIR}" "$@"

if [ -z "$INSTALL" ]; then
	cp "${BUILD_DIR}"/"${OUTPUT}" "${OUTPUT_DIR}"/"${OUTPUT}"
fi
