"""Narrow SSH-source repair. Does not reload/flush the experiment firewall."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shlex
import sys

from v5_vm_host import HOSTS, connect, remote
from v5_vm_inspect import PINS

CONFIG = "/etc/agentdlp/gateway-egress.env"
BACKUP = CONFIG + ".before-v5-host-20260910"
STAGED = "/home/zhang/gateway-egress.v5-host-20260910.env"
CHAIN = "AGENTDLP_GW_INPUT"


def values(text):
    return dict(line.split("=", 1) for line in text.splitlines()
                if line and not line.startswith("#"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Windows" or args.output.exists():
        raise ValueError("Windows host and fresh output required")
    password = sys.stdin.readline().rstrip("\r\n")
    client, _ = connect(HOSTS["gateway"], password, PINS["gateway"])
    audit = []

    def run(command, check=True):
        result = remote(client, command, input_text=password + "\n"
                        if command.startswith("sudo ") else None)
        audit.append({"command": command, "result": result})
        if check and result["exit"]:
            raise RuntimeError(result)
        return result["stdout"]

    try:
        before = run("sudo -S -p '' cat " + CONFIG)
        new = args.config.read_text(encoding="utf-8")
        old_values, new_values = values(before), values(new)
        key = "AGENTDLP_GATEWAY_MANAGEMENT_CIDR"
        if old_values.get(key) != "172.19.144.0/20":
            raise ValueError("Live management CIDR differs from reviewed snapshot")
        old_values[key] = "172.19.240.1/32"
        if old_values != new_values:
            raise ValueError("Unexpected non-management policy change")
        rules = run("sudo -S -p '' iptables -S " + CHAIN).splitlines()
        matches = [(i, line) for i, line in enumerate(rules)
                   if "--comment AGENTDLP_GW_MANAGEMENT_SSH " in line]
        if len(matches) != 1:
            raise ValueError("Expected one management rule")
        # iptables -S starts with -N; enumerate therefore equals rule number.
        index, old_rule = matches[0]
        old_args = shlex.split(old_rule)[2:]
        new_args = ["172.19.240.1/32" if arg == "172.19.144.0/20" else arg for arg in old_args]
        untouched = {c: run("sudo -S -p '' iptables -S " + c)
                     for c in ("AGENTDLP_GW_FORWARD", "AGENTDLP_GW_OUTPUT")}
        run("test ! -e " + BACKUP)
        run("sudo -S -p '' cp -a " + CONFIG + " " + BACKUP)
        sftp = client.open_sftp()
        try:
            try:
                sftp.stat(STAGED)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(STAGED)
            sftp.put(str(args.config), STAGED)
        finally:
            sftp.close()
        rendered = run("/usr/local/sbin/agentdlp-gateway-egress render " + STAGED)
        if "172.19.240.1/32" not in rendered:
            raise ValueError("Rendered policy missing new management source")
        run("sudo -S -p '' install -o root -g root -m 0600 " + STAGED + " " + CONFIG)
        run("sudo -S -p '' iptables -R " + CHAIN + " " + str(index) + " " + shlex.join(new_args))
        # Remove exactly the two reviewed console additions, retaining final allow.
        for suffix in (
            "-s 172.19.240.1/32 -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT",
            "-s 172.19.240.1/32 -i eth0 -p tcp",
        ):
            if "-A " + CHAIN + " " + suffix in rules:
                run("sudo -S -p '' iptables -D " + CHAIN + " " + suffix)
        second, _ = connect(HOSTS["gateway"], password, PINS["gateway"])
        try:
            check = remote(second, "hostname")
            if check["exit"] or check["stdout"].strip() != "agentdlp-gateway":
                raise ValueError("Independent SSH verification failed")
            audit.append({"independent_ssh": check})
        finally:
            second.close()
        for chain, expected in untouched.items():
            if run("sudo -S -p '' iptables -S " + chain) != expected:
                raise ValueError("Non-management chain drift: " + chain)
        final_rules = run("sudo -S -p '' iptables -S " + CHAIN).splitlines()
        expected_rules = [line for line in rules if line not in {
            "-A " + CHAIN + " -s 172.19.240.1/32 -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT",
            "-A " + CHAIN + " -s 172.19.240.1/32 -i eth0 -p tcp",
        }]
        expected_rules = [line.replace("172.19.144.0/20", "172.19.240.1/32")
                          if line == old_rule else line for line in expected_rules]
        if final_rules != expected_rules:
            raise ValueError("Unexpected input-chain change")
        run("sudo -S -p '' /usr/local/sbin/agentdlp-gateway-egress preflight")
        run("sudo -S -p '' /usr/local/sbin/agentdlp-gateway-egress status")
        audit.append({"repair": "verified", "backup": BACKUP,
                      "config_sha256": hashlib.sha256(new.encode()).hexdigest(),
                      "reboot_tested": False, "forward_output_unchanged": True})
    finally:
        client.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(audit, handle, indent=2)
        print(json.dumps(audit, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
