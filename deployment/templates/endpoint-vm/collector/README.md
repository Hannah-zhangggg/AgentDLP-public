# Root-owned eBPF collector (P0)

This opt-in deployment separates BPF loading from Agent workloads. The collector is a root-owned systemd template service; only it receives the minimal BPF attachment capabilities. Agent workloads must run with `NoNewPrivileges=yes` and `SystemCallFilter=~bpf`; Agent containers also retain `cap-drop=ALL` and `no-new-privileges`.

At install time the reviewed wrapper and already-built CO-RE loader are copied to root-owned paths below `/usr/local`. The collector writes raw evidence only below `/var/lib/agentdlp/ebpf-collector/<id>/`; it exports evidence only after the service has stopped. Root, the systemd manager, the collector runtime, kernel, and privileged workloads remain in the trusted computing base (TCB). A compromised TCB can disable collection or alter host state; stronger protection needs an independent VM or external collector.

## Installation

Stop Agent workloads first and retain a VM console or independent management SSH session.

```bash
make -C /home/zhang/agentdlp/experiments/ebpf-core all
cd /home/zhang/agentdlp/deployment/three-vm/endpoint-vm/collector
sudo ./agentdlp-ebpf-collectorctl install /home/zhang/agentdlp
```

## Per-workload lifecycle

```bash
sudo /usr/local/sbin/agentdlp-ebpf-collectorctl start RUN_ID \
  /sys/fs/cgroup/USER_SCOPE_CGROUP RUN_ID SESSION_ID opencode WORKLOAD_ID preflight 192.168.10.10
sudo /usr/local/sbin/agentdlp-ebpf-collectorctl stop RUN_ID
sudo /usr/local/sbin/agentdlp-ebpf-collectorctl export RUN_ID \
  /home/zhang/agentdlp/artifacts/events/RUN_ID-connect.jsonl 1000 1000
```

`start` rejects invalid identifiers, non-cgroup-v2 paths, concurrent collectors with the same ID, and missing root-owned runtime files. The system journal is the lifecycle record. Do not make the collector state directory writable by Agent users or containers.

## Paper wording

**English.** AgentDLP treats eBPF loading and collection as a host-level trusted service. Workload processes execute with `bpf()` denied by seccomp, while a root-owned collector exclusively owns the loader, hook lifecycle, pinned objects, and evidence directory. This boundary addresses the cross-container visibility of privileged eBPF tracing identified by He *et al.* [Cross Container Attacks, USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/he) and follows the trusted-load-time enforcement model of Patel *et al.* [KRAKENGUARD, NSDI 2026](https://www.usenix.org/conference/nsdi26/presentation/patel). The host root and privileged workloads remain part of the TCB.

**中文。** AgentDLP 将 eBPF 装载与采集收敛为主机级可信服务：工作负载通过 seccomp 禁止 `bpf()`，由 root 所有的 collector 独占 loader、hook 生命周期、pinned 对象和证据目录。该边界针对 He 等人在 Cross Container Attacks（USENIX Security 2023）中指出的特权 eBPF 跨容器可见性问题，并采用 Patel 等人在 KRAKENGUARD（NSDI 2026）中体现的可信装载时约束思路。主机 root 与特权工作负载属于 TCB。
