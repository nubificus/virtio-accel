project('virtio-accel', 'c',
  meson_version : '>=1.1',
  default_options : ['prefix=/'],
  version : run_command('sh', '-c',
    'git submodule update --init >/dev/null && ' +
    'scripts/common/generate-version.sh .',
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
make_sh = files(meson.project_source_root() + '/scripts/make.sh')
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
  meson.add_install_script(make_sh, make_bin,
    meson.current_source_dir(), build_dir_src, 'virtio_accel.ko',
    'modules_install',
    'BUILD_DIR=' + build_dir_virtio_accel,
    skip_if_destdir : true)

  meson.add_dist_script(
    'scripts/dist.sh',
    'virtio-accel',
    get_option('buildtype'),
    'DEBUG',
    debug,
    'PROFILING',
    opt_profiling.to_int().to_string(),
    )
endif

# helper vars for parent projects
version = meson.project_version()

gen_vm_artifacts = custom_target('gen-vm-artifacts',
  command : ['scripts/gen-vm-artifacts.sh',
    meson.project_source_root(),
    meson.project_build_root(),
    'DEBUG=' + debug + ' PROFILING=' + opt_profiling.to_int().to_string(),
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
  'Enable profiling': opt_profiling,
  },
  section : 'Configuration',
  bool_yn : true)
