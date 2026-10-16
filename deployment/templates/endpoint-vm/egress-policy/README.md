# Endpoint Egress Policy

This directory installs AgentDLP-owned nftables, controlled DNS and audit rules without flushing unrelated host policy. The deployer uses preflight, automatic rollback and explicit confirmation.

## Scope and migration

Current policy assets retain an `AGENT_UID` compatibility filter for the existing VM deployment. The target design identifies the workload by designated cgroup and network namespace, with UID/GID as supporting identity rather than the security boundary. The collector records cgroup ID, PID/start time, namespace inodes, UID/GID, container/Pod ID and socket cookie so policy evidence can be attributed to that workload.

This is not a whole-host boundary. root, the host collector and privileged workloads are TCB; arbitrary network namespaces and public IPv6 are not validated. Explicit proxy traffic still requires Gateway CONNECT/DoH/raw-TCP enforcement.

## Files

- `agentdlp-endpoint-egress`: install, preflight, apply, confirm, status, rollback and uninstall.
- `agentdlp-endpoint-egress.service`: confirmed boot-time policy.
- `endpoint-egress.env.example`: reviewed topology, management, UID-compatibility and workspace parameters.

## Safe deployment

Keep the VM console available and stop Agent workloads before applying policy.

```bash
cd /home/zhang/agentdlp/deployment/three-vm/endpoint-vm/egress-policy
cp endpoint-egress.env.example /tmp/endpoint-egress.env
$EDITOR /tmp/endpoint-egress.env
sudo ./agentdlp-endpoint-egress install /tmp/endpoint-egress.env
sudo /usr/local/sbin/agentdlp-endpoint-egress preflight
sudo /usr/local/sbin/agentdlp-endpoint-egress apply
```

Open a second management SSH session, check `status`, Gateway DNS and proxy health, then confirm. If any check fails, do not confirm; wait for automatic rollback or run `rollback` from the console.

```bash
sudo /usr/local/sbin/agentdlp-endpoint-egress status
sudo /usr/local/sbin/agentdlp-endpoint-egress confirm
```

For reboot validation, arm the reboot rollback before restarting and disarm it only after a new SSH session and policy checks succeed. `uninstall` removes only AgentDLP-owned rules/units and preserves the reviewed configuration for audit.

Earlier VM runs validated rollback, reboot recovery, explicit proxy/DNS, selected direct/DoH/QUIC blocking and controlled ULA evidence. Those runs predate the current dataset-v2 injector and do not constitute v2 evaluation or public IPv6 validation. The old controlled-redirect port is retained only as a disabled compatibility option.
