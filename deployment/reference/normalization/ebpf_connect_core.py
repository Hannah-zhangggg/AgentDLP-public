#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORE_LOADER = ROOT / "experiments" / "ebpf-core" / "connect_observer"
CORE_READY_PREFIX = "observing connect4/connect6/sendmsg4/sendmsg6 on cgroup: "
RFC1918_NETWORKS = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _transport(protocol: int, socket_type: int) -> str:
    if protocol == socket.IPPROTO_TCP or socket_type == socket.SOCK_STREAM:
        return "tcp"
    if protocol == socket.IPPROTO_UDP or socket_type == socket.SOCK_DGRAM:
        return "udp"
    return "unknown"


def _application_protocol(transport: str, port: int) -> str:
    if transport == "udp" and port == 443:
        return "quic"
    if transport == "tcp" and port == 443:
        return "tls"
    if port == 53:
        return "dns"
    return "unknown"


def _read_process(pid: int) -> dict[str, Any]:
    process: dict[str, Any] = {"pid": pid}
    try:
        status = Path(f"/proc/{pid}/status").read_text(
            encoding="utf-8",
            errors="replace",
        )
        for line in status.splitlines():
            if line.startswith("PPid:"):
                process["ppid"] = int(line.split()[1])
                break
    # /proc is a best-effort enrichment layer.  A short-lived task may exit
    # after BPF records the event but before this userspace reader opens it.
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
        process["ppid"] = None
    try:
        process["executable"] = os.readlink(f"/proc/{pid}/exe")
    except (FileNotFoundError, PermissionError, OSError):
        process["executable"] = None
    try:
        entries = Path(f"/proc/{pid}/cgroup").read_text(
            encoding="utf-8",
        ).splitlines()
        unified = next(
            (
                line.split(":", 2)[2]
                for line in entries
                if line.startswith("0::")
            ),
            None,
        )
        process["cgroup_path"] = unified
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
        process["cgroup_path"] = None
    return process


def _namespace_inode(pid: int, namespace: str) -> int | None:
    try:
        target = os.readlink(f"/proc/{pid}/ns/{namespace}")
        return int(target.removeprefix(f"{namespace}:[").removesuffix("]"))
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        return None


def _pid_start_time(pid: int) -> int | None:
    """Return Linux /proc starttime ticks; it disambiguates recycled PIDs."""
    try:
        # The second field is parenthesized and may itself contain spaces.
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        return int(stat.rsplit(") ", 1)[1].split()[19])
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError, ValueError):
        return None


def _workload_runtime_ids(cgroup_path: str | None) -> tuple[str | None, str | None]:
    """Best-effort Docker/containerd ID and Kubernetes Pod UID from cgroup naming."""
    if not cgroup_path:
        return None, None
    import re

    container = re.search(r"(?:docker-|cri-containerd-|crio-)?([0-9a-f]{64})(?:\.scope)?", cgroup_path)
    pod = re.search(r"pod([0-9a-fA-F_]{8,})(?:\.slice|/|$)", cgroup_path)
    return (container.group(1) if container else None, pod.group(1).replace("_", "-") if pod else None)


def _workload_identity(pid: int, cgroup_id: int, uid: int, gid: int, socket_cookie: int, process: dict[str, Any]) -> dict[str, Any]:
    container_id, pod_id = _workload_runtime_ids(process.get("cgroup_path"))
    return {
        "cgroup_id": str(cgroup_id),
        "pid": pid,
        "pid_start_time_ticks": _pid_start_time(pid),
        "pid_namespace_inode": _namespace_inode(pid, "pid"),
        "mount_namespace_inode": _namespace_inode(pid, "mnt"),
        "network_namespace_inode": _namespace_inode(pid, "net"),
        "uid": uid,
        "gid": gid,
        "container_id": container_id,
        "pod_id": pod_id,
        "socket_cookie": str(socket_cookie),
        "resolution": "procfs_best_effort",
    }


def _required_int(event: dict[str, Any], name: str) -> int:
    try:
        return int(event[name])
    except KeyError as exc:
        raise ValueError(f"raw CO-RE event is missing field: {name}") from exc
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"raw CO-RE event field {name!r} is not an integer"
        ) from exc


def _decode_comm(event: dict[str, Any]) -> str:
    try:
        comm_hex = event["comm_hex"]
    except KeyError as exc:
        raise ValueError(
            "raw CO-RE event is missing field: comm_hex"
        ) from exc
    if not isinstance(comm_hex, str):
        raise ValueError("raw CO-RE event field 'comm_hex' is not a string")
    try:
        return bytes.fromhex(comm_hex).decode("utf-8", errors="replace")
    except ValueError as exc:
        raise ValueError(
            "raw CO-RE event field 'comm_hex' is not valid hexadecimal"
        ) from exc


def event_to_record(
    event: dict[str, Any],
    *,
    realtime_offset_ns: int,
    run_id: str,
    session_id: str | None,
    harness_id: str,
    workload_id: str,
    experiment_group: str,
    source_ip: str | None,
) -> dict[str, Any]:
    event_kind = event.get("event_kind", "connect_attempt")
    event_types = {
        "connect_attempt": ("connect_observed", "connect_observed"),
        "connect_syscall_result": ("connect_result", "connect_result"),
        "tcp_established": ("connect_established", "connect_established"),
        "tcp_closed": ("connect_closed", "connect_closed"),
        "udp_sendmsg_attempt": (
            "udp_sendmsg_observed",
            "udp_sendmsg_observed",
        ),
        "udp_sendmsg_result": (
            "udp_sendmsg_result",
            "udp_sendmsg_result",
        ),
    }
    if event_kind not in event_types:
        raise ValueError(f"unsupported CO-RE event_kind: {event_kind!r}")
    timestamp_monotonic_ns = _required_int(event, "timestamp_ns")
    cgroup_id = _required_int(event, "cgroup_id")
    socket_cookie = _required_int(event, "socket_cookie")
    pid = _required_int(event, "pid")
    tid = _required_int(event, "tid")
    uid = _required_int(event, "uid")
    gid = _required_int(event, "gid")
    family = _required_int(event, "family")
    protocol = _required_int(event, "protocol")
    socket_type = _required_int(event, "socket_type")
    destination_port = _required_int(event, "destination_port")
    source_port = int(event.get("source_port") or 0)
    if not 0 <= source_port <= 65535:
        raise ValueError(
            "raw CO-RE event field 'source_port' is outside 0..65535"
        )
    policy_mode = event.get("policy_mode", "observe")
    action = event.get("action", "observed")
    rule_matched = event.get("rule_matched", False)

    if policy_mode not in {"observe", "would_redirect", "redirect"}:
        raise ValueError(f"unsupported policy_mode: {policy_mode!r}")
    if action not in {"observed", "would_redirect", "redirected"}:
        raise ValueError(f"unsupported connect action: {action!r}")
    if not isinstance(rule_matched, bool):
        raise ValueError("raw CO-RE event field 'rule_matched' is not boolean")

    try:
        destination_ip = event["destination_ip"]
    except KeyError as exc:
        raise ValueError(
            "raw CO-RE event is missing field: destination_ip"
        ) from exc
    if not isinstance(destination_ip, str):
        raise ValueError(
            "raw CO-RE event field 'destination_ip' is not a string"
        )
    if family not in (socket.AF_INET, socket.AF_INET6):
        raise ValueError(f"unsupported address family in raw CO-RE event: {family}")
    try:
        socket.inet_pton(family, destination_ip)
    except OSError as exc:
        raise ValueError(
            f"invalid destination_ip for address family {family}: "
            f"{destination_ip!r}"
        ) from exc
    if not 0 <= destination_port <= 65535:
        raise ValueError(
            "raw CO-RE event field 'destination_port' is outside 0..65535"
        )

    observed_source_ip = event.get("source_ip")
    if observed_source_ip is not None:
        if not isinstance(observed_source_ip, str):
            raise ValueError("raw CO-RE event field 'source_ip' is not a string")
        try:
            socket.inet_pton(family, observed_source_ip)
        except OSError as exc:
            raise ValueError(
                f"invalid source_ip for address family {family}: "
                f"{observed_source_ip!r}"
            ) from exc

    redirected_destination: dict[str, Any] | None = None
    redirected_ip = event.get("redirected_destination_ip")
    redirected_port = int(event.get("redirected_destination_port", 0))
    if rule_matched:
        if not isinstance(redirected_ip, str):
            raise ValueError(
                "matched redirect event is missing redirected_destination_ip"
            )
        try:
            ipaddress.IPv4Address(redirected_ip)
        except ipaddress.AddressValueError as exc:
            raise ValueError(
                f"invalid redirected_destination_ip: {redirected_ip!r}"
            ) from exc
        if not 1 <= redirected_port <= 65535:
            raise ValueError(
                "redirected_destination_port must be in 1..65535"
            )
        redirected_destination = {
            "ip": redirected_ip,
            "port": redirected_port,
        }
    elif redirected_ip is not None or redirected_port != 0:
        raise ValueError(
            "unmatched event must not contain a redirected destination"
        )

    if action == "would_redirect" and (
        policy_mode != "would_redirect" or not rule_matched
    ):
        raise ValueError("would_redirect action is inconsistent with policy")
    if action == "redirected" and (
        policy_mode != "redirect" or not rule_matched
    ):
        raise ValueError("redirected action is inconsistent with policy")
    if action == "observed" and rule_matched:
        raise ValueError("matched rule must emit a redirect decision action")

    transport = _transport(protocol, socket_type)
    timestamp_ns = timestamp_monotonic_ns + realtime_offset_ns
    timestamp = datetime.fromtimestamp(
        timestamp_ns / 1_000_000_000,
        timezone.utc,
    ).isoformat()
    process = _read_process(pid)
    process.update(
        {
            "tid": tid,
            "uid": uid,
            "gid": gid,
            "comm": _decode_comm(event),
            "cgroup_id": str(cgroup_id),
        }
    )
    process["workload_identity"] = _workload_identity(
        pid, cgroup_id, uid, gid, socket_cookie, process
    )
    original_destination = {
        "ip": destination_ip,
        "port": destination_port,
    }
    effective_destination = (
        redirected_destination
        if action == "redirected"
        else original_destination
    )
    reasons = {
        "connect_attempt": {
            "observed": "ebpf_cgroup_connect",
            "would_redirect": "controlled_target_would_redirect",
            "redirected": "controlled_target_redirected",
        }[action],
        "connect_syscall_result": "ebpf_sys_exit_connect",
        "tcp_established": "ebpf_cgroup_sockops_established",
        "tcp_closed": "ebpf_cgroup_sockops_closed",
        "udp_sendmsg_attempt": "ebpf_cgroup_udp_sendmsg",
        "udp_sendmsg_result": "ebpf_sys_exit_udp_send",
    }
    connect_return_code = event.get("connect_return_code")
    connect_errno = None
    if event_kind == "connect_syscall_result":
        if isinstance(connect_return_code, bool):
            raise ValueError("connect_return_code must be an integer")
        try:
            connect_return_code = int(connect_return_code)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "connect_syscall_result is missing connect_return_code"
            ) from exc
        if connect_return_code < 0:
            connect_errno = errno.errorcode.get(
                -connect_return_code,
                f"ERRNO_{-connect_return_code}",
            )
    else:
        connect_return_code = None

    send_return_code = event.get("send_return_code")
    send_errno = None
    if event_kind == "udp_sendmsg_result":
        if isinstance(send_return_code, bool):
            raise ValueError("send_return_code must be an integer")
        try:
            send_return_code = int(send_return_code)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "udp_sendmsg_result is missing send_return_code"
            ) from exc
        if send_return_code < 0:
            send_errno = errno.errorcode.get(
                -send_return_code,
                f"ERRNO_{-send_return_code}",
            )
    else:
        send_return_code = None

    if event_kind == "connect_attempt":
        connection_state = "attempted"
        source_port_status = "unavailable_at_cgroup_connect_hook"
    elif event_kind == "connect_syscall_result":
        if connect_return_code == 0:
            connection_state = "syscall_succeeded"
        elif connect_return_code in (-errno.EINPROGRESS, -errno.EALREADY):
            connection_state = "in_progress"
        else:
            connection_state = "syscall_failed"
        source_port_status = "unavailable_at_syscall_exit"
    elif event_kind == "tcp_established":
        connection_state = "established"
        source_port_status = "observed_at_cgroup_sockops"
    elif event_kind == "tcp_closed":
        connection_state = "closed"
        source_port_status = "observed_at_cgroup_sockops"
    elif event_kind == "udp_sendmsg_attempt":
        connection_state = "send_attempted"
        source_port_status = "unavailable_at_cgroup_sendmsg_hook"
    else:
        connection_state = (
            "send_succeeded" if send_return_code >= 0 else "send_failed"
        )
        source_port_status = "unavailable_at_syscall_exit"

    old_tcp_state = event.get("old_tcp_state")
    new_tcp_state = event.get("new_tcp_state")
    bytes_received = event.get("bytes_received")
    bytes_acked = event.get("bytes_acked")
    if event_kind == "tcp_closed":
        for field_name, value in (
            ("old_tcp_state", old_tcp_state),
            ("new_tcp_state", new_tcp_state),
            ("bytes_received", bytes_received),
            ("bytes_acked", bytes_acked),
        ):
            if isinstance(value, bool):
                raise ValueError(f"{field_name} must be an integer")
            try:
                parsed = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"tcp_closed is missing {field_name}"
                ) from exc
            if parsed < 0:
                raise ValueError(f"{field_name} must be non-negative")
            if field_name == "old_tcp_state":
                old_tcp_state = parsed
            elif field_name == "new_tcp_state":
                new_tcp_state = parsed
            elif field_name == "bytes_received":
                bytes_received = parsed
            else:
                bytes_acked = parsed
    else:
        old_tcp_state = None
        new_tcp_state = None
        bytes_received = None
        bytes_acked = None

    event_type, semantic_type = event_types[event_kind]
    configured_source_ip = source_ip
    if configured_source_ip:
        try:
            socket.inet_pton(family, configured_source_ip)
        except OSError:
            configured_source_ip = None
    return {
        "schema_version": 1,
        "event_type": event_type,
        "semantic_type": semantic_type,
        "timestamp": timestamp,
        "timestamp_monotonic_ns": timestamp_monotonic_ns,
        "run_id": run_id,
        "session_id": session_id,
        "harness_id": harness_id,
        "workload_id": workload_id,
        "experiment_group": experiment_group,
        "transport_protocol": transport,
        "application_protocol": _application_protocol(
            transport,
            destination_port,
        ),
        "source": {
            "ip": observed_source_ip or configured_source_ip,
            "port": source_port or None,
        },
        "destination": original_destination,
        "original_destination": original_destination,
        "redirected_destination": redirected_destination,
        "effective_destination": effective_destination,
        "action": action,
        "reason": reasons[event_kind],
        "process": process,
        "network": {
            "address_family": (
                "ipv4" if family == socket.AF_INET else "ipv6"
            ),
            "socket_type": socket_type,
            "protocol_number": protocol,
            "socket_cookie": str(socket_cookie),
            "policy_mode": policy_mode,
            "rule_matched": rule_matched,
            "source_port_status": source_port_status,
            "connection_state": connection_state,
            "connect_return_code": connect_return_code,
            "connect_errno": connect_errno,
            "send_return_code": send_return_code,
            "send_errno": send_errno,
            "tcp_old_state": old_tcp_state,
            "tcp_new_state": new_tcp_state,
            "tcp_bytes_received": bytes_received,
            "tcp_bytes_acked": bytes_acked,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Observe IPv4/IPv6 connect attempts from one cgroup "
            "without redirecting them"
        )
    )
    parser.add_argument(
        "--cgroup",
        required=True,
        type=Path,
        help="cgroup v2 directory to attach to",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="raw connect JSONL output",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--session-id")
    parser.add_argument("--harness-id", default="unknown")
    parser.add_argument("--workload-id", required=True)
    parser.add_argument(
        "--experiment-group",
        choices=("A", "B", "C", "preflight", "controlled-redirect"),
        required=True,
    )
    parser.add_argument(
        "--source-ip",
        help=(
            "Endpoint IP recorded as source; "
            "sockops events replace it with the observed local address"
        ),
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        help="seconds to observe; 0 means until interrupted",
    )
    parser.add_argument(
        "--ready-file",
        type=Path,
        help="touch this file only after both hooks are attached",
    )
    parser.add_argument(
        "--stop-file",
        type=Path,
        help="stop cleanly when this file appears",
    )
    parser.add_argument(
        "--mode",
        choices=("observe", "would-redirect", "redirect"),
        default="observe",
        help="observe, emit would_redirect, or rewrite one controlled target",
    )
    parser.add_argument("--target-ip")
    parser.add_argument("--target-port", type=int)
    parser.add_argument("--redirect-ip")
    parser.add_argument("--redirect-port", type=int)
    parser.add_argument(
        "--ack-controlled-redirect",
        action="store_true",
        help="required safety acknowledgement for --mode redirect",
    )
    return parser.parse_args(argv)


def _loader_path() -> Path:
    override = os.environ.get("AGENTDLP_EBPF_CORE_LOADER")
    return Path(override) if override else DEFAULT_CORE_LOADER


def _terminate_loader(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=3)


def _write_record(
    raw_line: str,
    output: TextIO,
    *,
    realtime_offset_ns: int,
    args: argparse.Namespace,
) -> None:
    try:
        raw_event = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"CO-RE loader emitted invalid JSON: {exc.msg}"
        ) from exc
    if not isinstance(raw_event, dict):
        raise RuntimeError("CO-RE loader emitted a JSON value that is not an object")
    try:
        record = event_to_record(
            raw_event,
            realtime_offset_ns=realtime_offset_ns,
            run_id=args.run_id,
            session_id=args.session_id,
            harness_id=args.harness_id,
            workload_id=args.workload_id,
            experiment_group=args.experiment_group,
            source_ip=args.source_ip,
        )
    except ValueError as exc:
        raise RuntimeError(f"invalid raw CO-RE event: {exc}") from exc
    output.write(
        json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    output.flush()


def run_observer(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError(
            "eBPF cgroup attachment requires root; "
            "run this observer with sudo"
        )
    if not args.cgroup.is_dir():
        raise FileNotFoundError(
            f"cgroup directory does not exist: {args.cgroup}"
        )
    if args.duration < 0:
        raise ValueError("--duration must be zero or positive")
    rule_values = (
        args.target_ip,
        args.target_port,
        args.redirect_ip,
        args.redirect_port,
    )
    if args.mode == "observe":
        if any(value is not None for value in rule_values):
            raise ValueError("observe mode does not accept a redirect rule")
        if args.ack_controlled_redirect:
            raise ValueError(
                "--ack-controlled-redirect is valid only in redirect mode"
            )
    else:
        if any(value is None for value in rule_values):
            raise ValueError(
                "would-redirect/redirect mode requires one complete rule"
            )
        for field_name in ("target_port", "redirect_port"):
            value = getattr(args, field_name)
            if not 1 <= value <= 65535:
                raise ValueError(f"--{field_name.replace('_', '-')} must be in 1..65535")
        for field_name in ("target_ip", "redirect_ip"):
            value = getattr(args, field_name)
            try:
                address = ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError as exc:
                raise ValueError(
                    f"--{field_name.replace('_', '-')} must be an IPv4 literal"
                ) from exc
            if not any(address in network for network in RFC1918_NETWORKS):
                raise ValueError(
                    f"--{field_name.replace('_', '-')} must be RFC1918/private"
                )
        if args.target_ip == args.redirect_ip:
            raise ValueError("--target-ip and --redirect-ip must differ")
        if args.mode == "redirect" and not args.ack_controlled_redirect:
            raise ValueError(
                "redirect mode requires --ack-controlled-redirect"
            )
        if args.mode != "redirect" and args.ack_controlled_redirect:
            raise ValueError(
                "--ack-controlled-redirect is valid only in redirect mode"
            )

    loader = _loader_path().resolve()
    if not loader.is_file():
        raise FileNotFoundError(f"CO-RE loader does not exist: {loader}")
    if not os.access(loader, os.X_OK):
        raise PermissionError(f"CO-RE loader is not executable: {loader}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.ready_file:
        args.ready_file.parent.mkdir(parents=True, exist_ok=True)
        args.ready_file.unlink(missing_ok=True)
    if args.stop_file:
        args.stop_file.parent.mkdir(parents=True, exist_ok=True)
        args.stop_file.unlink(missing_ok=True)

    realtime_offset_ns = time.time_ns() - time.monotonic_ns()
    started = time.monotonic()
    stop = False
    expected_shutdown = False
    ready = False
    output: TextIO | None = None
    pending_raw_lines: list[str] = []
    stderr_tail: list[str] = []
    old_sigint = signal.getsignal(signal.SIGINT)
    old_sigterm = signal.getsignal(signal.SIGTERM)

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop
        stop = True

    loader_command = [
        str(loader),
        "--json",
        "--mode",
        args.mode,
    ]
    if args.mode != "observe":
        loader_command.extend(
            [
                "--target-ip",
                args.target_ip,
                "--target-port",
                str(args.target_port),
                "--redirect-ip",
                args.redirect_ip,
                "--redirect-port",
                str(args.redirect_port),
            ]
        )
    if args.ack_controlled_redirect:
        loader_command.append("--ack-controlled-redirect")
    loader_command.append(str(args.cgroup))

    process = subprocess.Popen(
        loader_command,
        cwd=loader.parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_loader(process)
        raise RuntimeError("failed to open pipes for CO-RE loader")

    lines: queue.Queue[tuple[str, str | None]] = queue.Queue()

    def read_lines(kind: str, stream: TextIO) -> None:
        try:
            for line in stream:
                lines.put((kind, line.rstrip("\n")))
        finally:
            lines.put((kind, None))

    readers = [
        threading.Thread(
            target=read_lines,
            args=("stdout", process.stdout),
            daemon=True,
        ),
        threading.Thread(
            target=read_lines,
            args=("stderr", process.stderr),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    closed_streams: set[str] = set()

    try:
        while True:
            if args.stop_file and args.stop_file.exists():
                expected_shutdown = True
                break
            if stop:
                expected_shutdown = True
                break
            if (
                args.duration > 0
                and time.monotonic() - started >= args.duration
            ):
                try:
                    kind, line = lines.get_nowait()
                except queue.Empty:
                    expected_shutdown = True
                    break
            else:
                timeout = 0.2
                if args.duration > 0:
                    remaining = args.duration - (
                        time.monotonic() - started
                    )
                    timeout = max(0.0, min(timeout, remaining))

                try:
                    kind, line = lines.get(timeout=timeout)
                except queue.Empty:
                    kind = ""
                    line = None

            if kind and line is None:
                closed_streams.add(kind)
            elif kind == "stderr" and line is not None:
                stderr_tail.append(line)
                stderr_tail[:] = stderr_tail[-10:]
                expected_ready = f"{CORE_READY_PREFIX}{args.cgroup}"
                if line == expected_ready and not ready:
                    ready = True
                    output = args.output.open("a", encoding="utf-8")
                    if args.ready_file:
                        args.ready_file.touch()
                    print(
                        "Attached connect4/connect6/sendmsg4/sendmsg6 "
                        "observer to "
                        f"{args.cgroup}",
                        file=sys.stderr,
                    )
                    for pending in pending_raw_lines:
                        _write_record(
                            pending,
                            output,
                            realtime_offset_ns=realtime_offset_ns,
                            args=args,
                        )
                    pending_raw_lines.clear()
                elif line != expected_ready:
                    print(line, file=sys.stderr)
            elif kind == "stdout" and line is not None and line.strip():
                if ready:
                    if output is None:
                        raise RuntimeError(
                            "internal error: output is not open after ready"
                        )
                    _write_record(
                        line,
                        output,
                        realtime_offset_ns=realtime_offset_ns,
                        args=args,
                    )
                else:
                    pending_raw_lines.append(line)

            returncode = process.poll()
            if returncode is not None and len(closed_streams) == 2:
                if expected_shutdown:
                    break
                detail = stderr_tail[-1] if stderr_tail else "no stderr output"
                if not ready:
                    raise RuntimeError(
                        "CO-RE loader exited before reporting ready "
                        f"(status {returncode}): {detail}"
                    )
                raise RuntimeError(
                    "CO-RE loader exited unexpectedly "
                    f"(status {returncode}): {detail}"
                )
    finally:
        if args.ready_file:
            args.ready_file.unlink(missing_ok=True)
        if args.stop_file:
            args.stop_file.unlink(missing_ok=True)
        if output is not None:
            output.close()
        _terminate_loader(process)
        for reader in readers:
            reader.join(timeout=1)
        process.stdout.close()
        process.stderr.close()
        signal.signal(signal.SIGINT, old_sigint)
        signal.signal(signal.SIGTERM, old_sigterm)

    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run_observer(parse_args(argv))
    except (
        FileNotFoundError,
        PermissionError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
