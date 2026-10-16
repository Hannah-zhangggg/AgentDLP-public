# Traffic evidence model (P1)

AgentDLP records three non-interchangeable evidence layers.

1. **Endpoint L3/L4.** cgroup hooks and syscall completion tracepoints show that a
   scoped workload attempted a TCP/UDP operation, whether the syscall was rejected,
   and, for TCP, whether the socket later established or closed.  `sendmsg`,
   `sendto`, and `sendmmsg` share the UDP attempt/completion lifecycle. Connected
   IPv4 UDP, which bypasses cgroup `sendmsg4`, is captured by a cgroup-filtered
   `udp_sendmsg` kprobe. Because kprobes cannot obtain `socket_cookie`, that path is
   paired by TID and remains metadata/`Uncertain`. This is not wire-delivery evidence.
2. **Gateway/External arrival.** Proxy, firewall, and External service records are
   independent evidence that traffic reached the Gateway or External host.  They
   are required before claiming delivery beyond the Endpoint.
3. **Application semantics.** TLS termination, provider/protocol adapters, and
   endpoint wrappers recover semantics only where decoding is available.  Unknown
   or encrypted protocols remain metadata-only and are classified `Uncertain`.

The separation follows the observation that Linux host networking elements below
the transport stack can materially change traffic before it reaches the wire
(Sharafzadeh et al., *Understanding the Impact of Host Networking Elements on
Traffic Bursts*, NSDI 2023).  Consequently, cross-host correlation is conservative:
only a unique identity and time-window match can promote an observation; zero,
multiple, or clock-inconsistent candidates remain `Uncertain`.  Current harnesses
therefore run one scoped workload at a time, record clock offsets, and retain TCP
established/closed events through a bounded correlation window.  IPv6 public-path
coverage is deliberately out of scope until an address is available.

**Paper wording (English).** We separate endpoint L3/L4 evidence from independent
Gateway/External arrival evidence and from application-layer semantics.  Endpoint
hooks cover TCP lifecycle and UDP `sendmsg`/`sendto`/`sendmmsg` attempts, but never
by themselves prove wire delivery; ambiguous cross-host matches remain `Uncertain`.
This design follows Sharafzadeh et al.'s observation that host networking elements
can substantially alter traffic before it reaches the wire.

**论文表述（中文）。** 我们将 Endpoint 的 L3/L4 证据、Gateway/External 的独立到达
证据和应用层语义分离。Endpoint hook 覆盖 TCP 生命周期及 UDP
`sendmsg`/`sendto`/`sendmmsg` 尝试，但单独不能证明流量已经在线上到达；跨主机关联存在
歧义时一律保持 `Uncertain`。该设计呼应 Sharafzadeh 等人指出的主机网络组件可在流量到达
wire 前显著改变其行为这一结论。
