executable('compilation_check', ['src/compile_checker.cpp'],
    cpp_pch: 'pch/compiler_checker.hpp',
    include_directories: [common_inc, recycle_pool_inc],
    dependencies: [netio_psocket_dep, netdev_dep, spdlog_dep]
)
