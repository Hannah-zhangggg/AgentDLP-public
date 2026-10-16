from __future__ import annotations

import argparse
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int


def parse_endpoint(value: str) -> Endpoint:
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise ValueError(f"endpoint must be IP:PORT: {value}")
    ipaddress.ip_address(host.strip("[]"))
    parsed_port = int(port)
    if not 1 <= parsed_port <= 65535:
        raise ValueError(f"port is out of range: {value}")
    return Endpoint(host.strip("[]"), parsed_port)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: JSON record must be an object")
            records.append(value)
    return records


def _structured(record: dict[str, Any]) -> dict[str, Any]:
    content = record.get("content")
    if isinstance(content, dict) and isinstance(content.get("structured"), dict):
        return content["structured"]
    return record


def _experiment_group(record: dict[str, Any]) -> str | None:
    value = _structured(record).get("experiment_group") or record.get("experiment_group")
    return str(value) if value else None


def _destination(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("destination")
    return value if isinstance(value, dict) else {}


def _timestamp(record: dict[str, Any]) -> float | None:
    value = record.get("timestamp") or record.get("timestamp_start") or record.get("timestamp_recorded")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _matches_endpoint(record: dict[str, Any], endpoint: Endpoint) -> bool:
    destination = _destination(record)
    try:
        return (
            ipaddress.ip_address(str(destination.get("ip"))) == ipaddress.ip_address(endpoint.ip)
            and int(destination.get("port")) == endpoint.port
        )
    except (ValueError, TypeError):
        return False


def _provider_destination(record: dict[str, Any], networks: Iterable[Network]) -> bool:
    destination = _destination(record)
    try:
        address = ipaddress.ip_address(str(destination.get("ip")))
        port = int(destination.get("port"))
    except (ValueError, TypeError):
        return False
    return port == 443 and any(address in network for network in networks)


def _evidence(record: dict[str, Any]) -> dict[str, Any]:
    structured = _structured(record)
    process = structured.get("process") if isinstance(structured.get("process"), dict) else {}
    network = structured.get("network") if isinstance(structured.get("network"), dict) else {}
    return {
        "timestamp": record.get("timestamp"),
        "destination": _destination(record),
        "transport_protocol": record.get("transport_protocol"),
        "process": {
            key: process.get(key)
            for key in ("pid", "ppid", "comm", "executable", "cgroup_id", "cgroup_path")
            if process.get(key) is not None
        },
        "socket_cookie": network.get("socket_cookie"),
    }


def analyze(
    connects: list[dict[str, Any]],
    *,
    experiment_group: str,
    gateway_proxy: Endpoint,
    configured_proxy: Endpoint | None,
    provider_networks: list[Network],
    gateway_metadata: list[dict[str, Any]],
    provider_hosts: set[str],
    window_margin_seconds: float = 5.0,
) -> dict[str, Any]:
    selected = [record for record in connects if _experiment_group(record) in {None, experiment_group}]
    proxy_connections = [record for record in selected if _matches_endpoint(record, gateway_proxy)]
    configured_proxy_connections = (
        [record for record in selected if _matches_endpoint(record, configured_proxy)]
        if configured_proxy else []
    )
    direct_provider = [
        record for record in selected
        if (
            str(record.get("transport_protocol") or "").lower() == "tcp"
            and not _matches_endpoint(record, gateway_proxy)
            and _provider_destination(record, provider_networks)
        )
    ]
    possible_quic = [
        record for record in selected
        if (
            str(record.get("transport_protocol") or "").lower() == "udp"
            and not _matches_endpoint(record, gateway_proxy)
            and _provider_destination(record, provider_networks)
        )
    ]
    times = [value for value in (_timestamp(record) for record in selected) if value is not None]
    start = min(times) - window_margin_seconds if times else None
    end = max(times) + window_margin_seconds if times else None
    matching_flows = []
    for flow in gateway_metadata:
        host = str(flow.get("host") or "").lower()
        when = _timestamp(flow)
        if provider_hosts and host not in provider_hosts:
            continue
        if start is not None and (when is None or when < start or when > end):
            continue
        matching_flows.append(flow)

    reasons: list[str] = []
    if direct_provider and not matching_flows and experiment_group == "B":
        verdict = "direct_path_observed"
        reasons.append("the no-proxy control selected a direct Provider TCP/443 destination as expected")
        reasons.append("this control proves direct-path observability, not evasion of a configured proxy")
    elif direct_provider and not matching_flows:
        verdict = "confirmed_proxy_bypass"
        reasons.append("target cgroup selected a direct Provider TCP/443 destination despite a configured proxy")
        reasons.append("no matching Provider Flow was present at the explicit Gateway proxy in the time window")
    elif direct_provider:
        verdict = "proxy_bypass_suspected"
        reasons.append("direct Provider connection and Gateway Provider Flow both occurred; per-request correlation is incomplete")
    elif possible_quic and experiment_group == "B":
        verdict = "direct_path_observed"
        reasons.append("the no-proxy control selected UDP/443 to a supplied Provider IP; this is a possible QUIC/HTTP3 path")
    elif possible_quic:
        verdict = "proxy_bypass_suspected"
        reasons.append("target cgroup selected UDP/443 to a supplied Provider IP despite a configured proxy")
    elif proxy_connections and matching_flows:
        verdict = "no_bypass_observed"
        reasons.append("Provider activity reached the configured Gateway proxy and no direct Provider connection was observed")
    elif configured_proxy and configured_proxy != gateway_proxy and configured_proxy_connections:
        verdict = "proxy_honored_connection_failed"
        reasons.append("Agent attempted the configured unreachable proxy and no direct Provider connection was observed")
    else:
        verdict = "insufficient_evidence"
        reasons.append("no direct Provider connection and no matching successful Gateway Provider Flow established the request path")

    return {
        "schema_version": 1,
        "experiment_group": experiment_group,
        "verdict": verdict,
        "reasons": reasons,
        "counts": {
            "connect_events": len(selected),
            "gateway_proxy_connections": len(proxy_connections),
            "configured_proxy_connections": len(configured_proxy_connections),
            "direct_provider_connections": len(direct_provider),
            "possible_provider_quic_connections": len(possible_quic),
            "matching_gateway_provider_flows": len(matching_flows),
        },
        "evidence": {
            "direct_provider_connections": [_evidence(record) for record in direct_provider[:20]],
            "possible_provider_quic_connections": [_evidence(record) for record in possible_quic[:20]],
            "gateway_proxy_connections": [_evidence(record) for record in proxy_connections[:20]],
            "configured_proxy_connections": [_evidence(record) for record in configured_proxy_connections[:20]],
            "gateway_flow_ids": [flow.get("flow_id") for flow in matching_flows[:20]],
        },
        "limitations": [
            "cgroup/connect hooks observe the destination before connect but do not expose the selected source port",
            "a connect event proves destination selection/attempt, not TCP handshake or application-request success",
            "Provider IP/CIDR input must come from DNS evidence captured for this experiment window",
            "a mixed direct-and-proxied result remains suspected until DNS/SNI or per-connection Gateway correlation resolves it",
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify one AgentDLP proxy-bypass experiment group")
    parser.add_argument("--connect-log", required=True, type=Path)
    parser.add_argument("--gateway-metadata", required=True, type=Path)
    parser.add_argument("--experiment-group", choices=("A", "B", "C"), required=True)
    parser.add_argument("--gateway-proxy", required=True, help="expected AgentDLP proxy as IP:PORT")
    parser.add_argument("--configured-proxy", help="proxy configured for this group; omit for group B")
    parser.add_argument(
        "--provider-network", action="append", required=True,
        help="Provider IP or CIDR proven by experiment DNS/SNI evidence; repeat as needed",
    )
    parser.add_argument(
        "--provider-host", action="append", required=True,
        help="Provider host in Gateway metadata; repeat as needed",
    )
    parser.add_argument("--window-margin-seconds", type=float, default=5.0)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = analyze(
            read_jsonl(args.connect_log),
            experiment_group=args.experiment_group,
            gateway_proxy=parse_endpoint(args.gateway_proxy),
            configured_proxy=parse_endpoint(args.configured_proxy) if args.configured_proxy else None,
            provider_networks=[ipaddress.ip_network(value, strict=False) for value in args.provider_network],
            gateway_metadata=read_jsonl(args.gateway_metadata),
            provider_hosts={value.lower() for value in args.provider_host},
            window_margin_seconds=args.window_margin_seconds,
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Verdict: {report['verdict']}")
    print(f"Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
