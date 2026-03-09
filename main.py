"""
main.py — Entry point for the SSH-over-WebSocket tunnel.

Modes
-----
  (default)   Full tunnel: SOCKS proxy + TAP/tun2socks so *all* traffic
              is routed through the SSH tunnel (Windows, run as Admin).
  --socks     SOCKS-only: expose a local SOCKS proxy and nothing else.
              Works on any OS, no elevated privileges required.

Config selection
----------------
  Drop any number of *.toml files into the configs/ folder.
  If only one exists it is loaded automatically; otherwise you will be
  prompted to choose at startup.
"""

from __future__ import annotations

import argparse
import tomllib
import sys
import time
from pathlib import Path
from typing import Dict


# --------------------------------------------------------------------------- #
#                           Config folder loader                              #
# --------------------------------------------------------------------------- #

def _load_configs_dir() -> Dict[str, Dict]:
    configs_dir = Path(__file__).parent / "configs"
    if not configs_dir.is_dir():
        print("[!] No 'configs/' directory found next to main.py.")
        sys.exit(1)

    toml_files = sorted(configs_dir.glob("*.toml"))
    if not toml_files:
        print("[!] configs/ is empty — add at least one .toml config file.")
        sys.exit(1)

    configs = {}
    for path in toml_files:
        with open(path, "rb") as f:
            configs[path.stem] = tomllib.load(f)

    return configs


def select_config() -> Dict:
    """Load configs/ and let the user pick one if there are multiple."""
    configs = _load_configs_dir()

    if not configs:
        print("[!] No valid CONFIG dicts found in configs/.")
        sys.exit(1)

    if len(configs) == 1:
        name, cfg = next(iter(configs.items()))
        print(f"[*] Using config: {name}")
        return cfg

    print("\nAvailable configs:")
    names = list(configs.keys())
    for i, n in enumerate(names, 1):
        print(f"  [{i}] {n}")

    while True:
        try:
            choice = input("\nSelect config number: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(names):
                name = names[idx]
                print(f"[*] Using config: {name}")
                return configs[name]
        except (ValueError, KeyboardInterrupt):
            pass
        print("  Invalid choice, try again.")


# --------------------------------------------------------------------------- #
#                                   Main                                      #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH-over-WebSocket tunnel with optional full-system routing."
    )
    parser.add_argument(
        "--socks",
        action="store_true",
        help="SOCKS-only mode: expose a local SOCKS proxy without touching system routing.",
    )
    args = parser.parse_args()

    CONFIG = select_config()

    # Split "host:port" strings into separate values for downstream use
    def _split(key):
        val = CONFIG[key]
        host, _, port = val.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(f"config key '{key}' must be 'host:port', got: {val!r}")
        return host, int(port)

    proxy_host,  proxy_port  = _split("proxy")
    target_host, target_port = _split("target")

    # Expand into the flat keys that strategies and ws_tunnel expect
    CONFIG["PROXY_HOST"]  = proxy_host
    CONFIG["PROXY_PORT"]  = proxy_port
    CONFIG["TARGET_HOST"] = target_host
    CONFIG["TARGET_PORT"] = target_port

    # ------------------------------------------------------------------ #
    # 1. Establish the WebSocket / SSH tunnel
    # ------------------------------------------------------------------ #
    from tunnel_strategies import get_strategy
    from ssh_connector import connect_via_ws_and_start_socks

    try:
        strategy_cls   = get_strategy(CONFIG["mode"])
        ws_sock        = strategy_cls(CONFIG).establish()
        ssh_connection = connect_via_ws_and_start_socks(
            ws_socket        = ws_sock,
            ssh_user         = CONFIG["ssh_username"],
            ssh_password     = CONFIG["ssh_password"],
            local_socks_port = CONFIG["local_socks_port"],
        )
    except Exception as e:
        print(f"[!] Failed to establish tunnel: {e}")
        sys.exit(1)

    print(f"[+] SOCKS proxy up on 127.0.0.1:{CONFIG['local_socks_port']}")

    # ------------------------------------------------------------------ #
    # 2a. SOCKS-only mode — just keep the process alive
    # ------------------------------------------------------------------ #
    if args.socks:
        print("[+] Running in SOCKS-only mode. Ctrl-C to stop.")
        try:
            while True:
                time.sleep(999_999)
        except KeyboardInterrupt:
            print("[*] Shutting down.")
        return

    # ------------------------------------------------------------------ #
    # 2b. Full-tunnel mode — resolve hosts once, then hand off to tap.py
    # ------------------------------------------------------------------ #
    print("[*] Starting full-system tunnel via TAP/tun2socks …")

    import socket as _socket

    def _resolve(hostname: str):
        try:
            _socket.inet_aton(hostname)   # already an IP?
            return hostname
        except OSError:
            pass
        try:
            ip = _socket.gethostbyname(hostname)
            print(f"  Resolved {hostname} -> {ip}")
            return ip
        except _socket.gaierror:
            print(f"  [!] Could not resolve {hostname} — skipping bypass")
            return None

    bypass_hosts_raw = [
        proxy_host,
        target_host,
        CONFIG.get("front_domain", ""),
    ]
    resolved_bypass_ips = []
    seen = set()
    for h in bypass_hosts_raw:
        if not h:
            continue
        ip = _resolve(h)
        if ip and ip not in seen:
            resolved_bypass_ips.append(ip)
            seen.add(ip)

    from tap import run_tap

    try:
        run_tap(
            resolved_bypass_ips=resolved_bypass_ips,
            socks_port=CONFIG["local_socks_port"],
        )
    except KeyboardInterrupt:
        print("[*] Shutting down.")
    except Exception as e:
        print(f"[!] TAP error: {e}")


if __name__ == "__main__":
    main()
