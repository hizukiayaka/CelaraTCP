netio_inc = include_directories('inc')

netio_psocket = library('netio-psocket',
    'src/packet_socket_linux_impl.cpp',
    'src/packet_socket_linux.cpp',
    include_directories: [netio_inc, common_inc],
    cpp_pch: 'pch/packet_socket_linux_impl_pch.hpp',
    dependencies: netdev_dep
)

subdir('tests')
