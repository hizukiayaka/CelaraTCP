netio_inc = include_directories('inc')

netio_psocket = library('netio-psocket',
    'src/packet_socket_linux_impl.cpp',
    'src/packet_socket_linux.cpp',
    include_directories: [netio_inc, common_inc],
    dependencies: netdev_dep
)

netio_psocket_dep = declare_dependency(link_with: netio_psocket,
    include_directories: [netio_inc]
)

subdir('tests')
