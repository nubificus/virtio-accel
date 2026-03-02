project('virtio-accel', 'c',
  meson_version : '>=1.1',
  default_options : ['prefix=/'],
  version : run_command('sh', '-c',
    '(git submodule update --init >/dev/null 2>&1 || true) && ' +
    'scripts/common/generate-version.sh',
    env: {'SH_SCRIPTS_DIR': meson.project_source_root() / 'scripts' / 'common'},
    check: true).stdout().strip())

opt_kdir = get_option('kdir')
opt_profiling = get_option('profiling')

debug = '0'
opt_buildtype = get_option('buildtype')
if opt_buildtype == 'debug'
  debug = '1'
endif

subdir('include')
subdir('src')

env_vars = {
  'CC': meson.get_compiler('c').cmd_array()[0],
  'DEBUG': debug,
  'PROFILING': opt_profiling.to_int().to_string(),
}
if opt_kdir != 'default'
  env_vars += {'KDIR': opt_kdir}
endif

make_bin = find_program('make')
make_sh = meson.project_source_root() / 'scripts' / 'make.sh'
build_dir_src = meson.current_build_dir() / 'src'
build_dir_virtio_accel = build_dir_src / 'virtio_accel.ko.p'

virtio_accel = custom_target('virtio-accel',
  capture : false,
  console : true,
  build_by_default : not meson.is_subproject(),
  depend_files : files('Makefile'),
  input : virtio_accel_sources + virtio_accel_headers +
    virtio_accel_public_headers,
  output : ['virtio_accel.ko'],
  install : false,
  env : env_vars +
    {'BUILD_DIR': build_dir_virtio_accel },
  command : [make_sh, make_bin,
    meson.current_source_dir(), build_dir_src, 'virtio_accel.ko'])

compile_commands_json = custom_target('compile-commands-json',
  capture : false,
  console : true,
  build_always_stale : not meson.is_subproject(),
  build_by_default : not meson.is_subproject(),
  depend_files : files('Makefile'),
  depends : virtio_accel,
  output : ['compile_commands.json'],
  install : false,
  env : env_vars +
    {'BUILD_DIR': build_dir_virtio_accel },
  command : [make_sh, make_bin,
    meson.current_source_dir(), meson.current_build_dir(),
    'compile_commands.json', 'compile_commands.json'])

virtio_accel_headers_dep = declare_dependency(
  include_directories : include_directories('include', 'include' / 'uapi'))

virtio_accel_dep = declare_dependency(
  dependencies : virtio_accel_headers_dep,
  include_directories : include_directories('src'),
  sources: virtio_accel)

if not meson.is_subproject()
  env_vars_list = []
  foreach key, value : env_vars + {'BUILD_DIR': build_dir_virtio_accel }
    env_vars_list += key + '=' + value + ' '
  endforeach

  meson.add_install_script(make_sh, make_bin,
    meson.current_source_dir(), build_dir_src, 'virtio_accel.ko',
    'modules_install',
    env_vars_list,
    skip_if_destdir : true)
endif

version_only = meson.is_subproject() ? '--version-only' : ''
meson.add_dist_script(
  'scripts/dist.sh',
  '-n', meson.project_name(),
  '-v', meson.project_version(),
  '-t', get_option('buildtype'),
  '-a', 'profiling=' + opt_profiling.to_string(),
  '--pkg-config-path', ':'.join(get_option('pkg_config_path')),
  version_only)

# helper vars for parent projects
version = meson.project_version()

pkg_arch = run_command('sh', '-c',
  '. scripts/common/sh-common.sh; sh_print_arch',
  check: true).stdout().strip()
pkg_base_name = meson.project_name() + '_' + version + '_' + pkg_arch

gen_vm_artifacts = custom_target('gen-vm-artifacts',
  command : ['scripts/gen-vm-artifacts.sh',
    '-n', meson.project_name(),
    '-v', meson.project_version(),
    '-t', get_option('buildtype'),
    '-a', 'profiling=' + opt_profiling.to_string(),
    '-s', meson.project_source_root(),
    '-d', meson.project_build_root()],
  output : [
    pkg_base_name + '.tar.xz',
    pkg_base_name + '_fc.tar.xz',
    pkg_base_name + '_linux-image.tar.xz',
    pkg_base_name + '_fc-linux-image.tar.xz'],
  console : true,
  build_by_default : false,
  install : false)

alias_target('gen-vm-artifacts', gen_vm_artifacts)

summary({
  'Kernel source directory' : opt_kdir,
  'Enable profiling': opt_profiling,
  },
  section : 'Configuration',
  bool_yn : true)
