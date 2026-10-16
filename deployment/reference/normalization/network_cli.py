from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from normalization.adapters.generic.http import sanitize_structured
from normalization.core.event_schema import content_evidence, make_observation_event
from normalization.core.models import UnifiedEvent


NFT_FIELD = re.compile(r"(?:^|\s)([A-Z][A-Z0-9_]*)=([^\s]*)")
DNSMASQ_QUERY = re.compile(r"query\[([^]]+)]\s+(\S+)\s+from\s+(\S+)")


def parse_nft_log_line(line: str) -> dict[str, Any]:
    """Convert an AgentDLP nftables kernel/journal line to a normalized record.

    nftables log formats vary by logger.  We deliberately consume only stable
    packet-header fields and keep a hash of the original line for auditability.
    """
    fields = dict(NFT_FIELD.findall(line))
    if not fields.get("SRC") or not fields.get("DST") or not fields.get("PROTO"):
        raise ValueError("nft log line lacks SRC, DST or PROTO")
    transport = fields["PROTO"].lower()
    source_port = _integer(fields.get("SPT"))
    destination_port = _integer(fields.get("DPT"))
    reason = "endpoint_firewall"
    if "AGENTDLP_FORWARD" in line:
        reason = "gateway_forward_firewall"
    return {
        "transport_protocol": transport,
        "application_protocol": "unknown",
        "semantic_type": "network_bypass_attempt",
        "source": {"ip": fields["SRC"], "port": source_port},
        "destination": {"ip": fields["DST"], "port": destination_port},
        "action": "drop",
        "reason": reason,
        "network_log_id": "nft_" + hashlib.sha256(line.encode("utf-8")).hexdigest()[:24],
        "network": {
            "input_interface": fields.get("IN") or None,
            "output_interface": fields.get("OUT") or None,
            "packet_length": _integer(fields.get("LEN")),
        },
    }


def parse_dnsmasq_log_line(line: str) -> dict[str, Any]:
    match = DNSMASQ_QUERY.search(line)
    if match is None:
        raise ValueError("dnsmasq log line is not a query record")
    query_type, query_name, client_ip = match.groups()
    return {
        "transport_protocol": "udp",
        "application_protocol": "dns",
        "semantic_type": "dns_query",
        "source": {"ip": client_ip, "port": None},
        "destination": {"host": "controlled-resolver", "port": 53},
        "action": "observed",
        "reason": "controlled_dns_log",
        "network_log_id": "dns_" + hashlib.sha256(line.encode("utf-8")).hexdigest()[:24],
        "dns": {"qname": query_name, "qtype": query_type},
    }


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_network_line(line: str, input_format: str = "auto") -> dict[str, Any]:
    if input_format not in {"auto", "jsonl", "nft", "dnsmasq"}:
        raise ValueError(f"unsupported input format: {input_format}")
    if input_format in {"auto", "jsonl"}:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            if input_format == "jsonl":
                raise
        else:
            if not isinstance(value, dict):
                raise ValueError("JSON network record must be an object")
            return value
    if input_format == "dnsmasq" or (input_format == "auto" and "query[" in line):
        return parse_dnsmasq_log_line(line)
    return parse_nft_log_line(line)


def network_record_to_event(
    record: dict[str, Any],
    *,
    default_run_id: str,
    default_session_id: str | None = None,
    default_harness_id: str = "unknown",
    default_workload_id: str | None = None,
) -> UnifiedEvent:
    transport = str(record.get("transport_protocol", "unknown")).lower()
    source = record.get("source") if isinstance(record.get("source"), dict) else {}
    destination = record.get("destination") if isinstance(record.get("destination"), dict) else {}
    run_id = str(record.get("run_id") or default_run_id)
    session_id = record.get("session_id") or default_session_id or None
    harness_id = str(record.get("harness_id") or default_harness_id)
    workload_id = str(record.get("workload_id") or default_workload_id or harness_id)
    action = str(record.get("action") or "observed")
    reason = str(record.get("reason") or "network_control_observation")
    observed = {
        "action": action,
        "reason": reason,
        "experiment_group": record.get("experiment_group"),
        "process": record.get("process"),
        "dns": record.get("dns"),
        "tls": record.get("tls"),
        "network": record.get("network"),
    }
    observed = {key: value for key, value in observed.items() if value is not None}
    safe_observed = sanitize_structured(observed)
    evidence_bytes = json.dumps(observed, ensure_ascii=False, sort_keys=True).encode("utf-8")
    correlation = {
        "network_log_id": record.get("network_log_id"),
        "pid": (record.get("process") or {}).get("pid") if isinstance(record.get("process"), dict) else None,
        "ppid": (record.get("process") or {}).get("ppid") if isinstance(record.get("process"), dict) else None,
        "cgroup_id": (record.get("process") or {}).get("cgroup_id") if isinstance(record.get("process"), dict) else None,
        "socket_cookie": (record.get("network") or {}).get("socket_cookie") if isinstance(record.get("network"), dict) else None,
        "experiment_group": record.get("experiment_group"),
    }
    semantic_type = str(record.get("semantic_type") or "network_bypass_attempt")
    lifecycle_types = {
        "connect_observed",
        "connect_result",
        "connect_established",
        "connect_closed",
        "udp_sendmsg_observed",
        "udp_sendmsg_result",
    }
    event_type = (
        semantic_type if semantic_type in lifecycle_types else "bypass_network_attempt"
    )
    carrier_type = (
        "endpoint_ebpf" if reason.startswith("ebpf_") else "network_control_log"
    )
    return make_observation_event(
        event_type=event_type,
        flow_id=record.get("flow_id"),
        run_id=run_id,
        session_id=session_id,
        harness_id=harness_id,
        workload_id=workload_id,
        proxy_principal=record.get("proxy_principal"),
        timestamp=record.get("timestamp"),
        direction=str(record.get("direction") or "outbound"),
        transport_protocol=transport,
        application_protocol=str(record.get("application_protocol") or "unknown"),
        semantic_type=semantic_type,
        source=source,
        destination=destination,
        carrier={"type": carrier_type, "direction": str(record.get("direction") or "outbound")},
        request=None,
        response=None,
        content=content_evidence(evidence_bytes, structured=safe_observed),
        content_type="application/x-agentdlp-network-log",
        adapter_name="network_log_importer",
        parse_status="success" if source and destination else "partial",
        correlation=correlation,
        error=None if source and destination else {"code": "incomplete_network_identity"},
        event_id=str(record["event_id"]) if record.get("event_id") else None,
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Convert firewall, DNS or normalized network logs to unified events")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", default="network-import")
    parser.add_argument("--session-id")
    parser.add_argument("--harness-id", default="unknown")
    parser.add_argument("--workload-id")
    parser.add_argument("--input-format", choices=("auto", "jsonl", "nft", "dnsmasq"), default="auto")
    return parser.parse_args()


def main():
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.input.open(encoding="utf-8") as source, args.output.open("w", encoding="utf-8") as target:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                value = parse_network_line(line, args.input_format)
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"line {line_number}: {exc}") from exc
            event = network_record_to_event(
                value,
                default_run_id=args.run_id,
                default_session_id=args.session_id,
                default_harness_id=args.harness_id,
                default_workload_id=args.workload_id,
            )
            target.write(json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    print(f"Network events written: {count}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
