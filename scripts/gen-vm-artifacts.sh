#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -e

SCRIPTS_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null && pwd -P)
DOCKER_DIR=${SCRIPTS_DIR}/docker
SRC_DIR=${1:-"${MESON_SOURCE_ROOT:-"${SCRIPTS_DIR}/.."}"}
shift $(($# > 0 ? 1 : 0))
ARTIFACTS_DIR=${1:-"${MESON_BUILD_ROOT:-./vm-artifacts}"}
shift $(($# > 0 ? 1 : 0))
BUILD_ARGS=${1:-""}
shift $(($# > 0 ? 1 : 0))
PKG_NAME=${1:-virtio-accel}
shift $(($# > 0 ? 1 : 0))
PKG_VERSION=${1:-"$(sh "${SCRIPTS_DIR}/common/generate-version.sh" "")"}
shift $(($# > 0 ? 1 : 0))
RUN_DIR=/run/user/$(id -u)/${PKG_NAME}

printf "Package                       : %s\n" "${PKG_NAME}"
printf "Version                       : %s\n" "${PKG_VERSION}"
printf "Build args                    : %s\n" "${BUILD_ARGS}"
printf "Source directory              : %s\n" "${SRC_DIR}"
printf "Docker files directory        : %s\n" "${DOCKER_DIR}"
printf "Generated artifacts directory : %s\n\n" "${ARTIFACTS_DIR}"

mkdir -p "${ARTIFACTS_DIR}" "${RUN_DIR}"

cd "${SRC_DIR}"

printf "%s\n" 'Building virtio-accel artifacts'
# Build artifacts
res=0
docker build --network=host -f "${DOCKER_DIR}/vm-artifacts.dockerfile" \
	--build-arg "BUILD_ARGS=${BUILD_ARGS}" \
	--build-arg "PKG_NAME=${PKG_NAME}" \
	--build-arg "PKG_VERSION=${PKG_VERSION}" \
	--target artifacts \
	--output type=local,dest="${RUN_DIR}" "$@" . || res=$?

# Finalize and move files to artifacts dir
if [ "${res}" = 0 ]; then
	printf "\n"
	files=$(find "${RUN_DIR}" -name "${PKG_NAME}-${PKG_VERSION}*.tar.xz")
	uid=$(stat -c %u "${ARTIFACTS_DIR}")
	gid=$(stat -c %g "${ARTIFACTS_DIR}")
	for f in ${files}; do
		chown "${uid}":"${gid}" "${f}"
		mv "${f}" "${ARTIFACTS_DIR}/"
		printf "%s\n" "Created ${ARTIFACTS_DIR}/$(basename "${f}")"
	done
fi

# Cleanup
rm -rf "${RUN_DIR}"

exit "${res}"
