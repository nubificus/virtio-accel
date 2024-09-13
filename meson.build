project('virtio-accel', 'c',
  meson_version : '>=1.1',
  default_options : ['prefix=/'],
  version : run_command('sh', '-c',
    'git submodule update --init >/dev/null && ' +
    'scripts/common/generate-version.sh .',
    check: true).stdout().strip())

opt_kdir = get_option('kdir')
opt_zc = get_option('zc')
opt_profiling = get_option('profiling')

debug = '0'
opt_buildtype = get_option('buildtype')
if opt_buildtype == 'debug'
  debug = '1'
endif

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

env_vars = {
  'DEBUG': debug,
  'ZC': opt_zc.to_int().to_string(),
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

meson.add_install_script(make_sh, make_bin,
  meson.current_source_dir(), meson.current_build_dir(), 'virtio_accel.ko',
  'modules_install',
  'BUILD_DIR='+meson.current_build_dir() / 'virtio_accel.ko.p',
  skip_if_destdir : true)

meson.add_dist_script(
  'scripts/dist.sh',
  'virtio-accel',
  get_option('buildtype'),
  'DEBUG',
  debug,
  'ZC',
  opt_zc.to_int().to_string(),
  'PROFILING',
  opt_profiling.to_int().to_string(),
  )

# helper vars for parent projects
version = meson.project_version()

gen_vm_artifacts = custom_target('gen-vm-artifacts',
  command : ['scripts/gen-vm-artifacts.sh',
    meson.project_source_root(),
    meson.project_build_root(),
    'DEBUG=' + debug + ' ZC=' +opt_zc.to_int().to_string() +
      ' PROFILING=' + opt_profiling.to_int().to_string(), 
    meson.project_name(),
    meson.project_version()],
  output : [
    meson.project_name() + '-' + meson.project_version() + '-bin.tar.xz',
    meson.project_name() + '-' + meson.project_version() + '-fc-bin.tar.xz',
    meson.project_name() + '-' + meson.project_version() + '-linux-image.tar.xz',
    meson.project_name() + '-' + meson.project_version() + '-fc-linux-image.tar.xz'],
  console : true,
  build_by_default : false,
  install : false)

alias_target('gen-vm-artifacts', gen_vm_artifacts)

summary({
  'Kernel source directory' : opt_kdir,
  'Enable guest zero-copy': opt_zc,
  'Enable profiling': opt_profiling,
  },
  section : 'Configuration',
  bool_yn : true)
