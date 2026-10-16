from __future__ import annotations

import logging
import os
from collections.abc import Mapping


DEFAULT_CONNECT_PORTS = frozenset({443, 8443})
DEFAULT_CONNECT_TARGETS: frozenset[tuple[str, int]] = frozenset()
DEFAULT_DOH_HOSTS = frozenset(
    {
        "cloudflare-dns.com",
        "dns.google",
        "dns.quad9.net",
        "doh.opendns.com",
        "mozilla.cloudflare-dns.com",
    }
)
DOH_MEDIA_TYPES = ("application/dns-message", "application/dns-json")


def parse_connect_ports(raw: str | None) -> frozenset[int]:
    if raw is None or not raw.strip():
        return DEFAULT_CONNECT_PORTS
    ports = frozenset(int(part.strip()) for part in raw.split(",") if part.strip())
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("CONNECT ports must be integers between 1 and 65535")
    return ports


def parse_connect_targets(raw: str | None) -> frozenset[tuple[str, int]]:
    """Parse exact host:port CONNECT exemptions without opening a whole port."""
    if raw is None or not raw.strip():
        return DEFAULT_CONNECT_TARGETS
    targets: set[tuple[str, int]] = set()
    for part in raw.split(","):
        value = part.strip()
        if not value or value.count(":") != 1:
            raise ValueError("CONNECT targets must use host:port")
        host, port_text = value.rsplit(":", 1)
        host = host.strip().rstrip(".").lower()
        try:
            port = int(port_text)
        except ValueError as error:
            raise ValueError("CONNECT target ports must be integers") from error
        if not host or port < 1 or port > 65535:
            raise ValueError("CONNECT targets must use a non-empty host and valid port")
        targets.add((host, port))
    return frozenset(targets)


def connect_allowed(
    host: str,
    port: int,
    allowed_ports: frozenset[int],
    allowed_targets: frozenset[tuple[str, int]],
) -> bool:
    return port in allowed_ports or (host.rstrip(".").lower(), port) in allowed_targets


def parse_hosts(raw: str | None) -> frozenset[str]:
    if raw is None or not raw.strip():
        return DEFAULT_DOH_HOSTS
    return frozenset(
        host.strip().rstrip(".").lower() for host in raw.split(",") if host.strip()
    )


def is_doh_request(
    host: str,
    headers: Mapping[str, str],
    blocked_hosts: frozenset[str] = DEFAULT_DOH_HOSTS,
) -> bool:
    normalized_host = host.rstrip(".").lower()
    if normalized_host in blocked_hosts:
        return True
    media = " ".join(
        (
            headers.get("accept", ""),
            headers.get("content-type", ""),
        )
    ).lower()
    return any(media_type in media for media_type in DOH_MEDIA_TYPES)


def _deny(flow, reason: str) -> None:
    from mitmproxy import http

    flow.response = http.Response.make(
        403,
        f"AgentDLP Gateway policy denied {reason}\n".encode(),
        {"content-type": "text/plain; charset=utf-8"},
    )


def http_connect(flow) -> None:
    try:
        allowed_ports = parse_connect_ports(
            os.environ.get("AGENTDLP_CONNECT_ALLOWED_PORTS")
        )
        allowed_targets = parse_connect_targets(
            os.environ.get("AGENTDLP_CONNECT_ALLOWED_TARGETS")
        )
    except ValueError as error:
        logging.error("AgentDLP invalid CONNECT policy: %s", error)
        _deny(flow, "CONNECT because policy configuration is invalid")
        return
    if not connect_allowed(
        flow.request.host,
        flow.request.port,
        allowed_ports,
        allowed_targets,
    ):
        logging.warning(
            "AgentDLP denied CONNECT host=%s port=%s",
            flow.request.host,
            flow.request.port,
        )
        _deny(flow, f"CONNECT port {flow.request.port}")


def request(flow) -> None:
    if os.environ.get("AGENTDLP_BLOCK_DOH", "true").lower() != "true":
        return
    blocked_hosts = parse_hosts(os.environ.get("AGENTDLP_BLOCKED_DOH_HOSTS"))
    if is_doh_request(flow.request.host, flow.request.headers, blocked_hosts):
        logging.warning(
            "AgentDLP denied DoH host=%s path=%s",
            flow.request.host,
            flow.request.path,
        )
        _deny(flow, "DNS over HTTPS")
