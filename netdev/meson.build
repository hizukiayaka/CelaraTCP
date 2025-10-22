#project('netdev', 'cpp',
#  version: '0.0.1',
#  license: 'AGPL-3.0-or-later',
#  meson_version: '>=1.2.0',
#  default_options: [
#    'cpp_std=c++20',
#    'warning_level=2',
#    'c_std=c11',
#  ]
#)

netdev_inc = [include_directories('inc')]

netdev_sources = []
netdev_internal_dep = []

if not is_variable('common_inc')
  common_inc = include_directories('../common/inc')
endif

netdev_cpp_args = []

if 'linux' in target_machine.kernel()
  netdev_sources += [
                    'src/device/ethernet_netdev_linux.cpp',
                    'src/device/tun_gnu_linux_impl.cpp',
                    'src/tc/tc_egress_filter.cpp',
                    'src/tc/tc_egress_filter_lite.cpp',
                    'src/tc/tc_ingress_fwd.cpp',
                    ]

  netdev_inc += include_directories('src/tc')

  libnl_dep = dependency('libnl-route-3.0')
  libbpf_dep = dependency('libbpf')
  netdev_internal_dep += [ libnl_dep, libbpf_dep ]

  subdir('src/ebpf')
  netdev_inc += include_directories('src/ebpf')
  netdev_cpp_args += '-DEBPF_OBJECT_DIR="@0@"'.format(ebpf_obj_dir)
else
  error('no support OS')
endif

# Check for 128-bit integer support
cpp = meson.get_compiler('cpp')
has_int128 = cpp.compiles('''
  #include <cstdint>
  int main() {
    __int128 a = 0;
    unsigned __int128 b = 0;
    return 0;
  }
''', name: 'int128 support')

# Define dependencies and flags based on int128 support
if has_int128
  netdev_cpp_args += '-DHAVE_INT128=1'
else
  # Add abseil dependency when int128 is not available
  abseil_dep = dependency('absl', required: true)
  netdev_internal_dep += [ abseil_dep ]
  netdev_cpp_args += '-DHAVE_INT128=0'
endif

netdev = library('netdev',
    netdev_sources,
    include_directories: [netdev_inc, common_inc],
    dependencies: netdev_internal_dep,
    cpp_args: netdev_cpp_args,
    sources: netdev_ebpf_skeletons  # Ensure skeletons are generated first
)

netdev_dep = declare_dependency(link_with: netdev,
    include_directories: [netdev_inc]
)

subdir('tests')
