"""Read-only, host-key-pinned inspection of the existing three-VM deployment."""
import argparse
import json
from pathlib import Path
import platform
import sys

from v5_vm_host import HOSTS, connect, remote

PINS = {
    "gateway": "246fa47e239319d1cfa56897460699e8b602827c00e3aed046a403dae7930fff",
    "external": "0ca2b522b8a8dd83ea0d0d26b26d862d63a74490b0857d8d43fd47dee3aea9b4",
    "endpoint": "cc029db163b4caa4165c1d8d1b49f4f99f32792e3bcb3c6de243177073e6d65b",
}

CHECKS = {
    "gateway": [
        ("policy_config", "sudo -S -p '' cat /etc/agentdlp/gateway-egress.env"),
        ("policy_status", "sudo -S -p '' /usr/local/sbin/agentdlp-gateway-egress status"),
        ("manager_hash", "sha256sum /usr/local/sbin/agentdlp-gateway-egress"),
        ("containers", "docker inspect --format '{{.Name}} {{json .Mounts}} {{json .NetworkSettings.Ports}}' agentdlp-gateway-vm-mitmproxy-1 agentdlp-gateway-vm-controlled-redirect-mitmproxy-1"),
        ("service", "systemctl cat agentdlp-gateway-egress.service"),
        ("policy_backups", "sudo -S -p '' ls -la /etc/agentdlp"),
        ("upstream_health", "curl --noproxy '*' -k -sS --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}\\n' https://192.168.20.10:8443/"),
    ],
    "endpoint": [
        ("proxy_health", "curl --proxy http://192.168.10.1:8080 --noproxy '' -k -sS --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}\\n' https://192.168.20.10:8443/"),
        ("routing", "ip route get 192.168.20.10; timeout 3 getent hosts provider.external.test; timeout 3 getent hosts web.external.test"),
        ("collector_interface", "sudo -S -p '' cat /usr/local/sbin/agentdlp-ebpf-collectorctl"),
        ("running_collectors", "systemctl list-units --all --no-legend 'agentdlp*'; pgrep -x opencode; pgrep -x python3"),
        ("egress_policy", "sudo -S -p '' nft list ruleset"),
    ],
    "external": [
        ("running_provider", "ss -ltn '( sport = :8000 )'; pgrep -x python3"),
        ("service", "systemctl cat agentdlp-synthetic-remote-mcp.service"),
    ],
}

PATH_CHECKS = {
    "gateway": [
        ("proxy_settings", "docker inspect --format '{{json .Config.Cmd}}' agentdlp-gateway-vm-mitmproxy-1"),
        ("capture_files", "find /home/zhang/agentdlp/artifacts/three-vm/gateway/events -maxdepth 1 -type f -printf '%f %s\\n' | tail -n 10"),
        ("proxy_dns", "docker exec agentdlp-gateway-vm-mitmproxy-1 getent hosts web.external.test provider.external.test"),
    ],
    "endpoint": [
        ("egress_policy", "sudo -S -p '' nft list ruleset"),
        ("domain_proxy_health", "curl --proxy http://192.168.10.1:8080 --noproxy '' -k -sS --connect-timeout 3 --max-time 6 -w '\\nHTTP=%{http_code}\\n' https://web.external.test:8443/health"),
        ("direct_external_block", "curl --noproxy '*' -k -sS --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}\\n' https://192.168.20.10:8443/health"),
        ("provider_proxy_route", "curl --proxy http://192.168.10.1:8080 --noproxy '' -sS --connect-timeout 2 --max-time 3 -w '\\nHTTP=%{http_code}\\n' http://provider.external.test:8000/health"),
    ],
    "external": [],
}

POST_CHECKS = {
    "gateway": [
        ("policy_status", "sudo -S -p '' /usr/local/sbin/agentdlp-gateway-egress status"),
        ("containers", "docker ps --format '{{.Names}} {{.Status}}'"),
        ("config_hash", "sudo -S -p '' sha256sum /etc/agentdlp/gateway-egress.env /etc/agentdlp/gateway-egress.env.before-v5-host-20260910"),
    ],
    "external": [
        ("provider_stopped", "ss -ltn '( sport = :8000 )'; systemctl is-active agentdlp-v5vm-provider-r1"),
        ("original_services", "docker ps --format '{{.Names}} {{.Status}}'; systemctl is-active agentdlp-synthetic-remote-mcp.service"),
    ],
    "endpoint": [
        ("collectors_stopped", "systemctl list-units --state=running --no-legend 'agentdlp-ebpf-collector@*'"),
        ("disk", "df -h /home/zhang; du -sh /home/zhang/v5vm-pilot-r1"),
    ],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--paths", action="store_true")
    parser.add_argument("--post", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Windows":
        raise ValueError("SSH must originate on the Windows host")
    if args.output.exists():
        raise FileExistsError(args.output)
    password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        raise ValueError("Password required on stdin")
    records = []
    for role in HOSTS:
        client, key = connect(HOSTS[role], password, PINS[role])
        try:
            for name, command in (POST_CHECKS if args.post else PATH_CHECKS if args.paths else CHECKS)[role]:
                row = {"role": role, "check": name, "host_key_sha256": key,
                       "result": remote(client, command, input_text=password + "\n"
                                        if command.startswith("sudo ") else None)}
                records.append(row)
                print(json.dumps(row, ensure_ascii=True), flush=True)
        finally:
            client.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2)


if __name__ == "__main__":
    main()
