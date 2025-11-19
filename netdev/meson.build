netdev_inc = [include_directories('inc')]

libnl_dep = dependency('libnl-route-3.0')

netdev_sources = ['src/virtual_netdev.cpp']

if not is_variable('celaratcp_com_inc')
  celaratcp_com_inc = include_directories('../common/inc')
endif

libnl_dep = dependency('', required: false)
libbpf_dep = dependency('', required: false)
if 'linux' in target_machine.kernel()
  netdev_sources += 'src/tun_gnu_linux_impl.cpp'
  libnl_dep = dependency('libnl-route-3.0')
  libbpf_dep = dependency('libbpf')
  subdir('ebpf')
  netdev_inc += include_directories('ebpf')
else
  error('no support OS')
endif

netdev = library('netdev',
    netdev_sources,
    include_directories: [netdev_inc, celaratcp_com_inc],
    cpp_pch: 'pch/virtual_netdev_pch.hpp',
    dependencies: [libnl_dep, libbpf_dep],
    sources: netdev_ebpf_skeletons  # Ensure skeletons are generated first
)

netdev_dep = declare_dependency(link_with: netdev,
    include_directories: [netdev_inc]
)

subdir('tests')
