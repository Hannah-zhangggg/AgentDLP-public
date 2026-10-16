"""Windows-host SSH entry for v5. Credentials read from stdin, never persisted."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import sys

if os.environ.get("AGENTDLP_PARAMIKO_PATH"):
    sys.path.insert(0, os.environ["AGENTDLP_PARAMIKO_PATH"])
import paramiko

HOSTS = {"gateway": "172.19.244.119", "external": "172.19.252.150", "endpoint": "172.19.247.191"}


def connect(host, password, fingerprint=None):
    transport = paramiko.Transport(socket.create_connection((host, 22), timeout=8))
    transport.start_client(timeout=10)
    key = hashlib.sha256(transport.get_remote_server_key().asbytes()).hexdigest()
    if fingerprint and key != fingerprint:
        transport.close()
        raise ValueError("SSH host key changed")
    transport.auth_password("zhang", password)
    client = paramiko.SSHClient()
    client._transport = transport
    return client, key


def remote(client, command, timeout=30, input_text=None):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if input_text is not None:
        stdin.write(input_text)
        stdin.flush()
    stdin.channel.shutdown_write()
    data, error = stdout.read().decode("utf-8", "replace"), stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return {"exit": code, "stdout": data, "stderr": error}


PROBE = """hostname
cat /etc/machine-id
uname -r
ip -br address
ip route
df -h /home/zhang /tmp
free -m
python3 --version
ss -ltn
docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null
systemctl list-units --state=running --no-legend 'agentdlp*'
command -v opencode
test ! -x /home/zhang/.opencode/bin/opencode || /home/zhang/.opencode/bin/opencode --version
ls -l /usr/local/sbin/agentdlp-ebpf-collectorctl
find /home/zhang -maxdepth 2 -type d -name '*v5*' -o -name '*v4s*'
"""


def preflight(password):
    def one(role, host):
        client = None
        try:
            client, key = connect(host, password)
            return {"role": role, "host": host, "host_key_sha256": key, "probe": remote(client, PROBE)}
        except Exception as exc:
            return {"role": role, "host": host, "error": type(exc).__name__ + ": " + str(exc)}
        finally:
            if client:
                client.close()
    results = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(one, role, host) for role, host in HOSTS.items()]
        for future in as_completed(futures):
            row = future.result()
            print(json.dumps(row, ensure_ascii=True), flush=True)
            results.append(row)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--network-diagnostics", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Windows":
        raise ValueError("SSH connections must originate on Windows host")
    if args.output.exists():
        raise FileExistsError("preflight output exists")
    password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        raise ValueError("password required on stdin")
    global PROBE
    if args.network_diagnostics:
        PROBE = """hostname
ping -c 2 -W 1 192.168.10.1
ping -c 2 -W 1 192.168.20.1
ip neigh
ps -eo comm | sort | uniq -c
"""
    results = preflight(password)
    password = ""
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(results, handle, indent=2)
    return int(any("error" in row for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
