"""The dual-network checker flags uplink overlap and wrong-interface routes without touching the host."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("netcheck", Path(__file__).resolve().parents[2] / "scripts/netcheck.py")
netcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netcheck)

ADDRESSES = [
    {"ifname": "enp1s0", "addr_info": [{"family": "inet", "local": "10.20.30.40", "prefixlen": 16}]},
    {"ifname": "wlp0s20f3", "addr_info": [{"family": "inet", "local": "192.168.88.50", "prefixlen": 24}]},
]
ROUTES = [{"dst": "default", "dev": "enp1s0", "gateway": "10.20.0.1"}]


def levels(findings):
    return [level for level, _ in findings]


def test_exact_wifi_subnet_and_wifi_route_is_clean():
    findings = netcheck.analyze(ADDRESSES, ROUTES, "192.168.88.0/24",
                                {"192.168.88.1": {"dev": "wlp0s20f3", "prefsrc": "192.168.88.50"}}, "0", None)
    assert "CRITICAL" not in levels(findings) and "OK" in levels(findings)


def test_overlap_wrong_interface_and_vpn_routes_are_critical():
    findings = netcheck.analyze(ADDRESSES, ROUTES, netcheck.CODE_DEFAULT_ALLOWED,
                                {"192.168.88.1": {"dev": "enp1s0", "gateway": "10.20.0.1"}, "192.168.89.1": None},
                                "1", {"AdvertiseRoutes": ["192.168.88.0/24"]})
    text = " ".join(message for _, message in findings)
    assert levels(findings).count("CRITICAL") == 4
    assert "overlaps the internet uplink" in text and "internet uplink enp1s0" in text and "Tailscale" in text


def test_wifi_detection_returns_only_wireless_subnet_and_refuses_uplink_overlap():
    routes = ROUTES + [{"dst": "default", "dev": "wlp0s20f3", "gateway": "192.168.88.1", "metric": 600}]
    found = netcheck.wifi_networks(ADDRESSES, routes, {"wlp0s20f3"})
    assert found == [{"interface": "wlp0s20f3", "network": "192.168.88.0/24", "address": "192.168.88.50", "gateway": "192.168.88.1"}]
    overlapping = [ADDRESSES[0], {"ifname": "wlp0s20f3", "addr_info": [{"family": "inet", "local": "10.20.99.5", "prefixlen": 24}]}]
    import pytest
    with pytest.raises(SystemExit, match="overlaps"):
        netcheck.wifi_networks(overlapping, routes, {"wlp0s20f3"})


def test_wifi_default_route_is_not_mistaken_for_the_internet_uplink():
    wifi_only = [{"dst": "default", "dev": "wlp0s20f3", "gateway": "192.168.88.1"}]
    findings = netcheck.analyze(ADDRESSES[1:], wifi_only, "192.168.88.0/24",
                                {"192.168.88.1": {"dev": "wlp0s20f3", "prefsrc": "192.168.88.50"}}, "0", None, {"wlp0s20f3"})
    assert "CRITICAL" not in levels(findings) and "OK" in levels(findings)
