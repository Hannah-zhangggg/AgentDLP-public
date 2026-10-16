# Capture and deployment source

`reference/normalization` contains protocol/event normalization; `reference/proxy` contains Gateway capture; `reference/host` contains historical Windows-host orchestration helpers. `templates` contains egress-policy and collector service templates. `../collectors` contains eBPF and native tracing source, and `../experiments/live-cases/frozen-code` contains the live study's instrumentation and injection implementation.

The reference runners preserve their original environment assumptions. Configure paths, interfaces, host addresses and independently verified SSH host keys for your own deployment; no live environment is automatically started by the public verification commands. `tools/deployment_preflight.py` checks only configuration structure.

A fresh three-host deployment has not been validated as part of this publication update. Native tools, supported Linux kernels, tracing permissions, provider access and harness dependencies must be provisioned separately. Docker functional tests do not reproduce the three independent VM observation boundaries. Secrets must remain outside tracked files.
