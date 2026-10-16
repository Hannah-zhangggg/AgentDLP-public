# Dependencies

Statistics verification uses the Python standard library. Detector dependencies are fixed in `replay.txt`; the artifact validation used Python 3.14.4. `live-recorded-versions.json` records versions observed in the live study, while `deployment-dependencies.json` is an import inventory, not a fully verified installation lockfile.

Native tracing needs a C compiler and ptrace permissions. eBPF additionally needs a supported BTF-enabled Linux kernel, clang/LLVM, bpftool, libbpf/libelf/zlib development packages, make and appropriate capabilities. Historical host helpers use Paramiko. Live workloads require separately installed harnesses, tools and provider access. No drawing dependencies are included.
