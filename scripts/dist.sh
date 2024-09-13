#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# generate .version file
SCRIPTS_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null && pwd -P)
cd "${MESON_SOURCE_ROOT}" || exit 1
PKG_VERSION="$(sh "${SCRIPTS_DIR}"/common/generate-version.sh "" --no-dirty)"
echo "${PKG_VERSION}" >"${MESON_DIST_ROOT}/.version"

# parse script args
PKG_NAME=$1
shift $(($# > 0 ? 1 : 0))
BUILD_TYPE=$1
shift $(($# > 0 ? 1 : 0))
REPO_URL=$(git remote get-url origin |
	sed 's/git@github.com:\(.*\)\.git/https:\/\/github.com\/\1/g')

build_args=""
c=$((0))
for v in "$@"; do
	[ -z "$v" ] && continue

	if [ $((c % 2)) -eq 0 ]; then
		build_args="${build_args}$v="
	else
		build_args="${build_args}$v "
	fi
	c=$((c + 1))
done

printf "Package    : %s\n" "${PKG_NAME}"
printf "Version    : %s\n" "${PKG_VERSION}"
printf "Build type : %s\n" "${BUILD_TYPE}"
printf "Repo URL   : %s\n" "${REPO_URL}"
printf "Build args : %s\n\n" "${build_args}"

cd "${MESON_DIST_ROOT}" || exit 1

# generate binary dist
printf "%s\n\n" 'Generating binary distribution'
"${SCRIPTS_DIR}"/gen-vm-artifacts.sh \
	"${MESON_SOURCE_ROOT}" "$(dirname "${MESON_DIST_ROOT}")" \
	"${build_args}" "${PKG_NAME}" "${PKG_VERSION}"
