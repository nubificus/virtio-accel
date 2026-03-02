#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -e

SCRIPTS_DIR="$(cd -- "$(dirname -- "$0")" >/dev/null && pwd -P)"
SH_SCRIPTS_DIR="${SCRIPTS_DIR}/common"
# shellcheck source=scripts/common/dist-common.sh
. "${SH_SCRIPTS_DIR}/dist-common.sh"

main() {
	parse_args "$@"

	printf 'Package    : %s\n' "$DIST_PKG_NAME"
	printf 'Version    : %s\n' "$DIST_PKG_VERSION"
	printf 'Repo URL   : %s\n' "$DIST_REPO_URL"
	printf 'Build type : %s\n' "$DIST_BUILD_TYPE"
	printf 'Meson args : %s\n\n' "$DIST_BUILD_ARGS"

	printf 'Generating version file\n'
	generate_version_file

	if [ "$DIST_VERSION_ONLY" -eq 1 ]; then
		return
	fi

	cd "$MESON_DIST_ROOT" || sh_error "Could not change to ${MESON_DIST_ROOT}"

	printf 'Generating binary distribution\n\n'
	"$SCRIPTS_DIR"/gen-vm-artifacts.sh \
		-n "$DIST_PKG_NAME" \
		-v "$DIST_PKG_VERSION" \
		-t "$DIST_BUILD_TYPE" \
		--raw-build-args "$DIST_BUILD_ARGS" \
		-s "$MESON_SOURCE_ROOT" \
		-d "$(dirname "$MESON_DIST_ROOT")"
}

main "$@"
