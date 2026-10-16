# CO-RE Endpoint Observer

`connect_observer.bpf.c`, `connect_observer.c` and `connect_observer.h` implement the libbpf/CO-RE event source used by `scripts/observe/ebpf-connects.py`. The supported observation path records TCP connect/lifecycle and selected UDP send metadata for a designated workload cgroup, including socket and namespace-aware identity fields.

Build requirements are clang/LLVM, libbpf, libelf, zlib, pkg-config, bpftool and matching kernel headers. The target needs cgroup v2, BTF, BPF cgroup hooks and ring buffer support. Generated headers, objects, skeletons and loaders are local artifacts.

The host collector owns program loading, hooks, maps/ring buffer and evidence output. Agent workloads must not load BPF. Observation metadata does not itself prove application delivery or semantics; Gateway/External and protocol/wrapper evidence provide those layers.

The older single-rule RFC1918 TCP `would-redirect`/`redirect` mode is retained as an explicit historical experiment. It is not the current behavior-consistency mechanism and does not claim general TLS, UDP, IPv6 or transparent-proxy support.
