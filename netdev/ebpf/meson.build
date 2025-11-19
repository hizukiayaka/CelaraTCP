ebpf_sources = ['steering_multiq.bpf.c',
  'xmit_filter.bpf.c',
  'xdp_tcp_filter.bpf.c',
  'xdp_test.bpf.c',
  ]  # List of eBPF source files

ebpf_objects = []
foreach src : ebpf_sources
  ebpf_objects += custom_target(
    src.split('.')[0] + '_bpf',
    input: src,
    output: src.split('.')[0] + '.o',
    command: [
      'clang',
      '-target', 'bpf',
      '-O2',
      '-c', '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )
endforeach

# Optionally, install the compiled eBPF objects
#install_data(ebpf_objects, install_dir: get_option('prefix') + '/lib/ebpf')
