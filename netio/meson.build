netio_inc = include_directories('inc')

install_headers(
    'inc/tcp_connection.hpp',
    'inc/internet_checksum.hpp',
    'inc/userspace_tcp_stack.hpp',
    subdir: meson.project_name()
)

netio_psocket_name = celaratcp_lib_prefix + 'psocket'
netio_psocket = library(netio_psocket_name,
    'src/packet_socket_linux_impl.cpp',
    'src/packet_socket_linux.cpp',
    include_directories: [netio_inc, common_inc],
    cpp_args: '-DPSOCKET_LOGGER_NAME="@0@"'.format(netio_psocket_name),
    dependencies: [netdev_dep, spdlog_dep],
    install: true,
    version: meson.project_version()
)
install_headers('inc/packet_socket_linux.hpp', subdir: meson.project_name())
pkg.generate(netio_psocket)

netio_psocket_dep = declare_dependency(link_with: netio_psocket,
    include_directories: [netio_inc],
    dependencies: [netdev_dep, spdlog_dep]
)

netio_raw_name = celaratcp_lib_prefix + 'raw'
netio_raw = library(netio_raw_name,
    'src/raw_ip_socket.cpp',
    include_directories: [netio_inc, common_inc],
    install: true,
    version: meson.project_version()
)
install_headers('inc/raw_ip_socket.hpp', subdir: meson.project_name())
pkg.generate(netio_raw)

netio_raw_dep = declare_dependency(link_with: netio_raw,
    include_directories: [netio_inc]
)

subdir('tests')
