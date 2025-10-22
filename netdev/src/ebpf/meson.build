ebpf_sources = ['steering_multiq.bpf.c',
  'xmit_filter.bpf.c',
  'tun_egress.bpf.c',
  'l3_egress.bpf.c',
  'l2_ingress_fwd.bpf.c',
  'l2_ingress_ring_l4.bpf.c',
  ]  # List of eBPF source files

ebpf_obj_dir = join_paths(get_option('prefix'), get_option('libdir'),
                          meson.project_name())

netdev_ebpf_skeletons = []
foreach src : ebpf_sources
  obj = custom_target(
    src.split('.')[0] + '_bpf',
    input: src,
    output: src.split('.')[0] + '.o',
    command: [
      'clang',
      '-target', 'bpf',
      '-O2',
      '-g',
      '-c', '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true,
    install: true,
    install_dir: ebpf_obj_dir
  )

  netdev_ebpf_skeletons += custom_target(
    src.split('.')[0] + '_skel',
    input: obj,
    output: src.split('.')[0] + '_skel.h',
    command: [
      'bpftool', 'gen', 'skeleton', '@INPUT@'
    ],
    capture: true,
    build_by_default: true
  )
endforeach
