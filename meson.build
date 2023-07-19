project('virtio-accel', 'c',
  meson_version : '>=1.1',
  version : run_command('sh', '-c',
    'git submodule update --init >/dev/null && ' +
    'scripts/common/generate-version.sh .',
    check: false).stdout().strip())

virtio_accel_sources = files([
  'virtio_accel-mgr.c',
  'virtio_accel-reqs.c',
  'virtio_accel.h',
  'accel.c',
  'virtio_accel-common.h',
  'virtio_accel-prof.c',
  'virtio_accel-sess.c',
  'accel.h',
  'virtio_accel-core.c',
  'virtio_accel-prof.h',
  'virtio_accel-zc.c'])

opt_kdir = get_option('kdir')
opt_debug = get_option('debug-mode')
opt_zc = get_option('zc')
opt_profiling = get_option('profiling')

env_vars = {
  'ZC': opt_zc.to_int().to_string(),
  'DEBUG': opt_debug.to_int().to_string(),
  'PROFILING': opt_profiling.to_int().to_string(),
}
if opt_kdir != 'default'
  env_vars += {'KDIR': opt_kdir}
endif

make_bin = find_program('make')
make_sh = files(meson.project_source_root() + '/scripts/make.sh')
virtio_accel = custom_target('virtio-accel',
  capture : false,
  console : true,
  build_by_default : not meson.is_subproject(),
  input : files('Makefile') + virtio_accel_sources,
  output : ['virtio_accel.ko'],
  install : false,
  env : env_vars +
    {'BUILD_DIR': meson.current_build_dir() / 'virtio_accel.ko.p'},
  command : [make_sh, make_bin,
    meson.current_source_dir(), meson.current_build_dir(), 'virtio_accel.ko'])

virtio_accel_headers_dep = declare_dependency(
  include_directories : include_directories('.'))

virtio_accel_dep = declare_dependency(
  include_directories : include_directories('.'),
  sources: virtio_accel)

opt_prefix = get_option('prefix')
if opt_prefix == '/usr/local'
  install_path = ''
else
  install_path = opt_prefix
endif
meson.add_install_script(make_sh, make_bin,
    meson.current_source_dir(), meson.current_build_dir(), 'virtio_accel.ko',
    'modules_install', 'INSTALL_MOD_PATH='+install_path,
    'BUILD_DIR='+meson.current_build_dir() / 'virtio_accel.ko.p')

summary({
  'Kernel source directory' : opt_kdir,
  'Enable debug': opt_debug,
  'Enable guest zero-copy': opt_zc,
  'Enable profiling': opt_profiling,
  },
  section : 'Configuration',
  bool_yn : true)
