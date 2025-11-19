netdev_inc = include_directories('inc')

libnl_dep = dependency('libnl-route-3.0')

netdev_sources = ['src/virtual_netdev.cpp']

if 'linux' in target_machine.kernel()
  netdev_sources += 'src/tun_gnu_linux_impl.cpp'
else
  error('no support OS')
endif

netdev = library('netdev',
    netdev_sources,
    include_directories: [netdev_inc, celaratcp_com_inc],
    cpp_pch: 'pch/virtual_netdev_pch.hpp',
    dependencies: [libnl_dep]
)

netdev_dep = declare_dependency(link_with: netdev,
    include_directories: [netdev_inc]
)

subdir('tests')
subdir('ebpf')
