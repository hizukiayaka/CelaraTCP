project(
    'celaratcp',
    'cpp',
    version: '0.0.9',
    license: 'AGPL-3.0-or-later',
    meson_version: '>=1.2.0',
    default_options : [
        'cpp_std=c++20',
        'warning_level=2',
        'c_std=c11',
    ]
)

add_project_arguments('-fcoroutines', language: ['cpp'])

subdir('contrib')
subdir('common')

subdir('netdev')
subdir('netio')
subdir('utils')
