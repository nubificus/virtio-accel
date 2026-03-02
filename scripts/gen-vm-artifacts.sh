#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -e

SCRIPTS_DIR="$(cd -- "$(dirname -- "$0")" >/dev/null && pwd -P)"
SH_SCRIPTS_DIR="${SCRIPTS_DIR}/common"
# shellcheck source=scripts/common/sh-common.sh
. "${SH_SCRIPTS_DIR}/sh-common.sh"

DOCKER_DIR="${SCRIPTS_DIR}/docker"
PKG_ARCH="$(sh_print_arch)"

SRC_DIR_DEFAULT="${MESON_SOURCE_ROOT:-"${SCRIPTS_DIR}/.."}"
ARTIFACTS_DIR_DEFAULT="${MESON_BUILD_ROOT:-'./vm-artifacts'}"

parse_args() {
	short_opts='n:v:t:a:s:d:'
	long_opts='pkg-name:,pkg-version:,build-type:,build-arg:,raw-build-args:'
	long_opts="${long_opts},src-dir:,artifacts-dir:"

	if ! getopt=$(getopt -o "$short_opts" --long "$long_opts" \
		-n "$SH_SCRIPT_NAME" -- "$@"); then
		sh_error 'Failed to parse args'
	fi

	eval set -- "$getopt"

	build_args=
	while true; do
		case "$1" in
		'-n' | '--pkg-name')
			# Package name
			[ -z "$2" ] &&
				sh_error "'$1' requires a non-empty string"
			pkg_name="$2"
			shift 2
			;;
		'-v' | '--pkg-version')
			# Package version
			[ -z "$2" ] &&
				sh_error "'$1' requires a non-empty string"
			pkg_version="$2"
			shift 2
			;;
		'-t' | '--build-type')
			# Build type
			[ -z "$2" ] &&
				sh_error "'$1' requires a non-empty string"
			build_type="$2"
			shift 2
			;;
		'-a' | '--build-arg')
			# Build args
			arg=$(echo "$2" | cut -d'=' -f1)
			value=$(echo "$2" | cut -d'=' -f2-)
			[ -z "${arg}" ] || [ -z "${value}" ] &&
				sh_error "'$1' requires a string of the form 'arg=value'"
			build_args="${build_args} -D${arg}=${value}"
			unset arg
			unset value
			shift 2
			;;
		'-s' | '--src-dir')
			# Source directory
			[ -z "$2" ] &&
				sh_error "'$1' requires a non-empty string"
			src_dir="$2"
			shift 2
			;;
		'-d' | '--artifacts-dir')
			# Artifacts directory
			[ -z "$2" ] &&
				sh_error "'$1' requires a non-empty string"
			artifacts_dir="$2"
			shift 2
			;;
		'--raw-build-args')
			# Raw build args (as passed to meson)
			[ -z "$2" ] &&
				sh_error "'$1' requires a non-empty string"
			build_args="${build_args} ${2}"
			shift 2
			;;
		--)
			shift
			break
			;;
		*)
			sh_error 'Internal error parsing args'
			;;
		esac
	done

	if [ -z "$pkg_name" ] || [ -z "$pkg_version" ] ||
		[ -z "$build_type" ]; then
		sh_error 'Package name, version or buildtype was not provided'
	fi

	src_dir="${src_dir:-"$SRC_DIR_DEFAULT"}"
	artifacts_dir="${artifacts_dir:-"$ARTIFACTS_DIR_DEFAULT"}"

	buildtype_arg="--buildtype=${build_type}"
	if [ "${build_args#*"$buildtype_arg"*}" = "$build_args" ]; then
		build_args="${build_args} ${buildtype_arg}"
	fi

	run_dir="/run/user/$(id -u)/${pkg_name}"

	unset short_opts
	unset long_opts
	unset buildtype_arg
}

generate_artifacts() {
	cd "$src_dir"

	# Build artifacts
	res=0
	docker build --network=host \
		-f "${DOCKER_DIR}/vm-artifacts.dockerfile" \
		--build-arg "BUILD_ARGS=${build_args}" \
		--build-arg "PKG_NAME=${pkg_name}" \
		--build-arg "PKG_VERSION=${pkg_version}" \
		--build-arg "PKG_ARCH=${PKG_ARCH}" \
		--target artifacts \
		--output type=local,dest="$run_dir" \
		. || res=$?

	# Finalize and move files to artifacts dir
	if [ "$res" != 0 ]; then
		cd - >/dev/null
		sh_log_error 'Failed to build artifacts' "$res"
		return
	fi

	printf "\n"
	base_name="${pkg_name}_${pkg_version}"
	files="$(find "$run_dir" -name "${base_name}*.tar.xz")"
	uid="$(stat -c %u "$artifacts_dir")"
	gid="$(stat -c %g "$artifacts_dir")"
	for f in ${files}; do
		chown "$uid":"$gid" "$f"
		mv "$f" "${artifacts_dir}/"
		printf 'Created %s\n' \
			"${artifacts_dir}/$(basename "$f")"
	done
}

main() {
	parse_args "$@"

	printf 'Package                       : %s\n' "$pkg_name"
	printf 'Version                       : %s\n' "$pkg_version"
	printf 'Architecture                  : %s\n' "$PKG_ARCH"
	printf 'Build type                    : %s\n' "$build_type"
	printf 'Meson args                    : %s\n' "$build_args"
	printf 'Source directory              : %s\n' "$src_dir"
	printf 'Docker files directory        : %s\n' "$DOCKER_DIR"
	printf 'Generated artifacts directory : %s\n\n' "$artifacts_dir"

	mkdir -p "$artifacts_dir" "$run_dir"

	printf 'Building %s artifacts\n' "$pkg_name"
	generate_artifacts

	rm -rf "$run_dir"
	exit "$res"
}

main "$@"
