project(
    'celaratcp',
    'cpp',
    version: '0.0.9',
    license: 'AGPL-3.0-or-later',
    meson_version: '>=1.2.0',
    default_options : [
        'cpp_std=c++23',
        'warning_level=2',
        'c_std=c23',
    ]
)

add_project_arguments('-DASIO_NO_DEPRECATED', language: ['cpp'])
add_project_arguments('-DASIO_NO_DYNAMIC_BUFFER_V1', language: ['cpp'])

spdlog_dep = dependency('spdlog', required: false)
if spdlog_dep.found()
  add_project_arguments('-DLOGGER_USE_SPDLOG', language: 'cpp')
endif

add_project_arguments('-fcoroutines', language: ['cpp'])

subdir('contrib')
subdir('common')

subdir('netdev')
subdir('netio')
subdir('utils')
