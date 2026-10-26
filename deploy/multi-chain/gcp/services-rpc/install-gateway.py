#!/usr/bin/env python3
"""Install Services-only RPC listeners; never modify Relayer/Envio listeners."""
import fcntl
import os
from pathlib import Path
import socket
import subprocess

LISTEN = "10.148.0.32"
SOURCE = "10.148.0.25/32"
BACKEND = "10.250.0.13"


def unit_text(chain, port, target):
    return f"""[Unit]
Description=Private {chain} RPC ingress for Psy Services only
Wants=network-online.target
After=network-online.target wg-quick@wg0.service

[Service]
ExecStart=/usr/bin/socat -d -d TCP4-LISTEN:{port},bind={LISTEN},reuseaddr,fork,range={SOURCE} TCP4:{BACKEND}:{target},connect-timeout=5
Restart=on-failure
RestartSec=3
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_UNIX

[Install]
WantedBy=multi-user.target
"""


def main():
    assert os.geteuid() == 0, "root required"
    assert Path("/usr/bin/socat").is_file(), "socat missing"
    with open("/run/psy-services-rpc-gateway.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        units = []
        for chain, port, target in [("sepolia", 28545, 8545), ("bsc", 28645, 8645)]:
            path = Path(f"/etc/systemd/system/parth-services-{chain}-rpc.service")
            content = unit_text(chain, port, target)
            if path.exists():
                assert path.read_text() == content, "existing unit differs; stop for review"
            else:
                with socket.socket() as probe:
                    probe.bind((LISTEN, port))
                units.append((path, content))
        # Preflight both ports before writing either unit.
        for path, content in units:
            with path.open("x") as file:
                file.write(content)
            path.chmod(0o644)
        names = [f"parth-services-{chain}-rpc.service" for chain in ("sepolia", "bsc")]
        subprocess.run(["systemd-analyze", "verify", *[f"/etc/systemd/system/{n}" for n in names]], check=True)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", *names], check=True)
        subprocess.run(["systemctl", "is-active", *names], check=True)
        print("Services source-only listeners ready; existing RPC listeners unchanged")


if __name__ == "__main__":
    main()
