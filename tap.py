"""
tap.py — TAP/tun2socks manager for the SSH-over-WS SOCKS proxy.

Called by main.py (not run standalone) after the SOCKS proxy is already up.
Hosts are resolved once in main.py and passed in as pre-resolved IPs.

To stop, press Ctrl-C in the main.py process.
tun2socks output is written to tun2socks.log in the same directory.
"""

from __future__ import annotations

import atexit
import subprocess
import sys
import time
import os
from typing import List, Optional

# --------------------------------------------------------------------------- #
#                                  SETTINGS                                   #
# --------------------------------------------------------------------------- #

SETTINGS = {
    "TUN2SOCKS_BIN":    os.path.join(os.path.dirname(os.path.abspath(__file__)), "tun2socks-windows-amd64.exe"),
    "TAP_ADAPTER_NAME": "tuntap0",
    "TAP_IP":           "10.0.0.1",
    "TAP_MASK":         "255.255.255.0",
    "TAP_GATEWAY":      "10.0.0.2",
    "TAP_METRIC":       5,
    "SOCKS_HOST":       "127.0.0.1",
    "SOCKS_VERSION":    5,
    "REAL_GATEWAY":     "",   # Auto-detected if empty
}

# --------------------------------------------------------------------------- #
#                               Internal state                                #
# --------------------------------------------------------------------------- #

_added_routes: List[tuple] = []
_tun2socks_proc: Optional[subprocess.Popen] = None


def _run(cmd: List[str]) -> None:
    subprocess.run(cmd, capture_output=True)


def _ps(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True, text=True, errors="replace",
    )
    return (result.stdout or "").strip()

# --------------------------------------------------------------------------- #
#                             Gateway detection                               #
# --------------------------------------------------------------------------- #

def detect_real_gateway() -> str:
    if SETTINGS["REAL_GATEWAY"]:
        return SETTINGS["REAL_GATEWAY"]
    result = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, errors="replace")
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            print(f"[+] Real gateway: {parts[2]}")
            return parts[2]
    raise RuntimeError("Could not detect real gateway. Set SETTINGS['REAL_GATEWAY'] manually.")

# --------------------------------------------------------------------------- #
#                              Bypass routes                                  #
# --------------------------------------------------------------------------- #

def add_bypass_route(ip: str, gateway: str) -> None:
    _run(["route", "add", ip, "mask", "255.255.255.255", gateway, "metric", "1"])
    _added_routes.append((ip, "255.255.255.255", gateway))
    print(f"  Bypass: {ip} -> {gateway}")


def remove_bypass_routes() -> None:
    for ip, mask, gw in _added_routes:
        if ip != "__ps_route__":
            _run(["route", "delete", ip, "mask", mask, gw])

# --------------------------------------------------------------------------- #
#                           TAP adapter setup                                 #
# --------------------------------------------------------------------------- #

def find_tap_adapter() -> str:
    name = _ps(
        "Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*TAP-Windows*' } "
        "| Select-Object -First 1 -ExpandProperty Name"
    )
    if not name:
        raise RuntimeError("No TAP-Windows adapter found. Install TAP-Windows from openvpn.net.")
    print(f"[+] Found TAP adapter: '{name}'")
    return name


def configure_tap_adapter() -> None:
    stable  = SETTINGS["TAP_ADAPTER_NAME"]
    current = find_tap_adapter()

    if current != stable:
        print(f"[*] Renaming '{current}' -> '{stable}'")
        _run(["netsh", "interface", "set", "interface", f"name={current}", f"newname={stable}"])
        time.sleep(1)

    print(f"[*] Configuring {stable} ...")
    _run(["netsh", "interface", "ip", "set", "address",
          f"name={stable}", "static",
          SETTINGS["TAP_IP"], SETTINGS["TAP_MASK"], SETTINGS["TAP_GATEWAY"]])
    time.sleep(2)


def _netsh_interfaces():
    """Return parsed rows from 'netsh interface ipv4 show interfaces'."""
    result = subprocess.run(
        ["netsh", "interface", "ipv4", "show", "interfaces"],
        capture_output=True, text=True, errors="replace",
    )
    if not result.stdout:
        return []
    return [
        line.split() for line in result.stdout.splitlines()
        if len(line.split()) >= 5 and line.split()[0].isdigit()
    ]


def raise_other_interface_metrics() -> None:
    tap = SETTINGS["TAP_ADAPTER_NAME"].lower()
    for parts in _netsh_interfaces():
        name = " ".join(parts[4:]).lower()
        if tap in name or "tun2socks" in name or "loopback" in name:
            continue
        if parts[3].lower() != "connected":
            continue
        _run(["netsh", "interface", "ipv4", "set", "interface", parts[0], "metric=9000"])


def restore_interface_metrics() -> None:
    for parts in _netsh_interfaces():
        _run(["netsh", "interface", "ipv4", "set", "interface", parts[0], "metric=automatic"])
    print("[*] Interface metrics restored.")

# --------------------------------------------------------------------------- #
#                         tun2socks + default route                           #
# --------------------------------------------------------------------------- #

def start_tun2socks(socks_port: int) -> None:
    global _tun2socks_proc
    bin_path = SETTINGS["TUN2SOCKS_BIN"]
    if not os.path.isfile(bin_path):
        raise FileNotFoundError(f"tun2socks not found at {bin_path!r}")

    socks    = f"socks{SETTINGS['SOCKS_VERSION']}://{SETTINGS['SOCKS_HOST']}:{socks_port}"
    log_path = os.path.join(os.path.dirname(bin_path), "tun2socks.log")
    log_file = open(log_path, "w")

    cmd = [bin_path, "-device", SETTINGS["TAP_ADAPTER_NAME"], "-proxy", socks, "-loglevel", "error"]
    print("[*] Starting tun2socks (log -> tun2socks.log)")
    _tun2socks_proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file)


def wait_for_tun2socks_interface() -> str:
    print("[*] Waiting for tun2socks tunnel interface ...")
    for _ in range(15):
        time.sleep(1)
        if _tun2socks_proc.poll() is not None:
            raise RuntimeError("tun2socks exited during startup — check tun2socks.log")
        idx = _ps(
            "Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*tun2socks*' "
            "-or $_.Name -like '*tun2socks*' } | Select-Object -First 1 -ExpandProperty ifIndex"
        )
        if idx:
            print(f"[+] tun2socks interface up (ifIndex={idx})")
            return idx
    raise RuntimeError("tun2socks tunnel interface did not appear — check tun2socks.log")


def add_default_route(idx: str) -> None:
    metric = SETTINGS["TAP_METRIC"]
    _run(["netsh", "interface", "ipv4", "set", "interface", idx, f"metric={metric}"])
    _ps(f"New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {idx} "
        f"-NextHop '0.0.0.0' -RouteMetric {metric} -ErrorAction SilentlyContinue")
    _added_routes.append(("__ps_route__", idx, "0.0.0.0"))
    print(f"[+] Default route -> tun2socks (ifIndex={idx}, metric={metric})")


def remove_default_route() -> None:
    for entry in _added_routes:
        if entry[0] == "__ps_route__":
            idx = entry[1]
            _ps(f"Remove-NetRoute -InterfaceIndex {idx} -DestinationPrefix '0.0.0.0/0' "
                f"-Confirm:$false -ErrorAction SilentlyContinue")

# --------------------------------------------------------------------------- #
#                                  Cleanup                                    #
# --------------------------------------------------------------------------- #

def stop_tun2socks() -> None:
    if _tun2socks_proc and _tun2socks_proc.poll() is None:
        _tun2socks_proc.terminate()
        try:
            _tun2socks_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _tun2socks_proc.kill()
        print("[*] tun2socks stopped.")


def cleanup() -> None:
    print("\n[*] Cleaning up ...")
    stop_tun2socks()
    remove_default_route()
    remove_bypass_routes()
    restore_interface_metrics()


atexit.register(cleanup)

# --------------------------------------------------------------------------- #
#                          Public entry point (called by main.py)             #
# --------------------------------------------------------------------------- #

def run_tap(resolved_bypass_ips: List[str], socks_port: int) -> None:
    """
    Set up TAP routing.  Called by main.py after:
      - The SOCKS proxy is already listening on socks_port
      - Bypass host IPs have already been resolved (passed in directly)

    Parameters
    ----------
    resolved_bypass_ips : list of IP strings that must bypass the tunnel
                          (proxy host, target host, front domain, etc.)
    socks_port          : the local SOCKS port tun2socks should connect to
    """
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Full-tunnel mode requires Administrator privileges.")
            sys.exit(1)
    except Exception:
        pass

    print("=" * 50)
    print("  tap.py — tun2socks tunnel manager")
    print("=" * 50)

    real_gw = detect_real_gateway()

    print("\n[*] Adding bypass routes ...")
    for ip in resolved_bypass_ips:
        add_bypass_route(ip, real_gw)

    configure_tap_adapter()
    start_tun2socks(socks_port)
    idx = wait_for_tun2socks_interface()
    raise_other_interface_metrics()
    add_default_route(idx)

    print(f"\n[+] Tunnel active. Bypass gateway: {real_gw}")
    print("[+] tun2socks output -> tun2socks.log")
    print("[+] Ctrl-C to stop.\n")

    while True:
        time.sleep(2)
        if _tun2socks_proc and _tun2socks_proc.poll() is not None:
            print("[!] tun2socks died — check tun2socks.log")
            break
