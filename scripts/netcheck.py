#!/usr/bin/env python3
"""Read-only dual-network safety check for a Suro development laptop (Linux).

Reports which interface reaches each router address, whether ROUTER_ALLOWED_NETWORKS overlaps the
internet-connected (default-route) network, and forwarding/VPN settings that could bridge networks.
It never changes interfaces, routes, firewall rules or services and never sends packets to routers.

    python3 scripts/netcheck.py --target 192.168.88.1
"""
import argparse
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENV_KEYS = ("ROUTER_ALLOWED_NETWORKS", "LAN_BIND_IP", "OPERATION_MODE", "ROUTER_WRITES_ENABLED", "TEST_ROUTERS")
CODE_DEFAULT_ALLOWED = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"


def run_json(*command):
    try:
        return json.loads(subprocess.run(command, capture_output=True, text=True, check=True, timeout=10).stdout or "null")
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def read_env(path):
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() in ENV_KEYS:  # Only non-secret keys are read.
                values[key.strip()] = value.strip()
    return values


def analyze(addresses, routes, allowed, target_routes, forwarding, tailscale, wireless=frozenset()):
    """Pure analysis so it can be tested. Returns (level, message) findings."""
    findings = []
    defaults = [r for r in routes if r.get("dst") == "default"]
    # The isolated network is reached over Wi-Fi, so a wireless default route is never the internet uplink.
    uplinks = {r.get("dev") for r in defaults} - set(wireless)
    if any(r.get("dev") in wireless for r in defaults):
        findings.append(("INFO", "The Wi-Fi also provides a default route; with Ethernet connected its metric decides which one wins."))
    uplink_networks = []
    for iface in addresses:
        for a in iface.get("addr_info", []):
            if a.get("family") == "inet" and iface["ifname"] in uplinks:
                uplink_networks.append((iface["ifname"], ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network))
    for name, network in uplink_networks:
        findings.append(("INFO", f"Internet uplink: {name} {network} (default route)"))
    permitted = [ipaddress.ip_network(n.strip(), strict=False) for n in allowed.split(",") if n.strip()]
    for net in permitted:
        for name, uplink in uplink_networks:
            if net.overlaps(uplink):
                findings.append(("CRITICAL", f"ROUTER_ALLOWED_NETWORKS entry {net} overlaps the internet uplink {name} {uplink}. "
                                 "Set it to the exact isolated Wi-Fi subnet(s) only."))
    if allowed == CODE_DEFAULT_ALLOWED:
        findings.append(("WARN", "ROUTER_ALLOWED_NETWORKS is the broad code default. Set exact isolated subnets in .env."))
    for target, route in target_routes.items():
        if not route:
            findings.append(("CRITICAL", f"{target}: no route; the isolated Wi-Fi is probably disconnected."))
            continue
        dev, via = route.get("dev"), route.get("gateway")
        if not any(ipaddress.ip_address(target) in n for n in permitted):
            findings.append(("CRITICAL", f"{target}: outside ROUTER_ALLOWED_NETWORKS; Suro will refuse it."))
        if dev in uplinks:
            findings.append(("CRITICAL", f"{target}: would leave through the internet uplink {dev}"
                             + (f" via {via}" if via else "") + ". Do not register this router until routing is fixed."))
        else:
            findings.append(("OK", f"{target}: reached through {dev}" + (f" via {via}" if via else " (directly attached)")
                             + f", source {route.get('prefsrc', '?')}"))
    if forwarding == "1":
        findings.append(("WARN", "IPv4 forwarding is on (Docker enables it). Docker sets the FORWARD policy to DROP; "
                         "check with 'sudo iptables -S FORWARD' and never add MASQUERADE/ACCEPT between the uplink and Wi-Fi."))
    if tailscale and (tailscale.get("AdvertiseRoutes") or tailscale.get("ExitNodeID") or tailscale.get("AdvertiseExitNode")):
        findings.append(("CRITICAL", "Tailscale advertises routes or uses an exit node; this can expose or reroute the isolated network."))
    return findings


def wifi_networks(addresses, routes, wireless):
    """Isolated Wi-Fi subnets and gateways; raises when one overlaps the internet uplink."""
    uplinks = {r.get("dev") for r in routes if r.get("dst") == "default" and r.get("dev") not in wireless}
    uplink_nets = [ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network
                   for i in addresses if i["ifname"] in uplinks for a in i.get("addr_info", []) if a.get("family") == "inet"]
    found = []
    for iface in addresses:
        if iface["ifname"] not in wireless:
            continue
        for a in iface.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            network = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network
            if any(network.overlaps(u) for u in uplink_nets):
                raise SystemExit(f"Wi-Fi subnet {network} overlaps the internet uplink; set ROUTER_ALLOWED_NETWORKS by hand.")
            gateway = next((r.get("gateway") for r in routes if r.get("dev") == iface["ifname"] and r.get("gateway")), None)
            found.append({"interface": iface["ifname"], "network": str(network), "address": a["local"], "gateway": gateway})
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env", type=Path, default=ROOT / ".env")
    parser.add_argument("--target", action="append", default=[], help="Router management IP to check (repeatable)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--detect-wifi", action="store_true", help="Print the connected Wi-Fi subnet(s) and gateway, then exit")
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or not shutil.which("ip"):
        raise SystemExit("Linux with iproute2 is required. On Windows see docs/development/dual-network-setup.md "
                         "(Get-NetIPConfiguration, Find-NetRoute -RemoteIPAddress).")
    wireless = {p.parent.name for p in Path("/sys/class/net").glob("*/wireless")}
    if args.detect_wifi:
        found = wifi_networks(run_json("ip", "-j", "addr") or [], run_json("ip", "-j", "route") or [], wireless)
        if not found:
            raise SystemExit("No connected Wi-Fi interface with an IPv4 address. Connect to the MikroTik Wi-Fi first.")
        print(json.dumps(found))
        return
    env = read_env(args.env)
    allowed = env.get("ROUTER_ALLOWED_NETWORKS", CODE_DEFAULT_ALLOWED)
    addresses = run_json("ip", "-j", "addr") or []
    routes = run_json("ip", "-j", "route") or []
    targets = {}
    for target in args.target:
        ipaddress.ip_address(target)
        result = run_json("ip", "-j", "route", "get", target)
        targets[target] = result[0] if result else None
    forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    tailscale = run_json("tailscale", "debug", "prefs") if shutil.which("tailscale") else None
    findings = analyze(addresses, routes, allowed, targets, forwarding, tailscale, wireless)
    if args.json:
        print(json.dumps({"env": env, "findings": findings}, indent=2))
    else:
        print("Interfaces:")
        for iface in addresses:
            inet = [f"{a['local']}/{a['prefixlen']}" for a in iface.get("addr_info", []) if a.get("family") == "inet"]
            print(f"  {iface['ifname']:<18} {iface.get('operstate', '?'):<8} {' '.join(inet) or '-'}")
        print(f"\nOPERATION_MODE={env.get('OPERATION_MODE') or '(unset: legacy ROUTER_WRITES_ENABLED=' + env.get('ROUTER_WRITES_ENABLED', 'false') + ')'}")
        print(f"ROUTER_ALLOWED_NETWORKS={allowed}\n")
        for level, message in findings:
            print(f"[{level}] {message}")
        if not args.target:
            print("[INFO] Add --target <router IP> to check which interface reaches a router.")
    raise SystemExit(1 if any(level == "CRITICAL" for level, _ in findings) else 0)


if __name__ == "__main__":
    main()
