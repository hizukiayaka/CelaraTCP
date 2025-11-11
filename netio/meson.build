netio_inc = include_directories('inc')

netio_psocket_name = 'netio-psocket'
netio_psocket = library(netio_psocket_name,
    'src/packet_socket_linux_impl.cpp',
    'src/packet_socket_linux.cpp',
    include_directories: [netio_inc, common_inc],
    cpp_args: '-DPSOCKET_LOGGER_NAME="@0@"'.format(netio_psocket_name),
    dependencies: [netdev_dep, spdlog_dep]
)

netio_psocket_dep = declare_dependency(link_with: netio_psocket,
    include_directories: [netio_inc],
    dependencies: [netdev_dep, spdlog_dep]
)

subdir('tests')
