import ipaddress
import socket
import ssl
from urllib.parse import urlparse
import httpx
from app.security.crypto import canonical, digest

STACKS = {
    "wifi": ("interface/wifi", "interface/wifi/access-list", "interface/wifi/registration-table"),
    "wireless": ("interface/wireless", "interface/wireless/access-list", "interface/wireless/registration-table"),
    "capsman": ("caps-man/interface", "caps-man/access-list", "caps-man/registration-table"),
}
PATHS = ["system/resource", "system/package", "interface", "ip/dhcp-server", "ip/dhcp-server/network",
         "ip/dhcp-server/lease", "ip/pool", "ip/address", "ip/arp", "ip/firewall/filter", "ip/firewall/address-list",
         "ipv6/firewall/filter", "interface/bridge", "interface/bridge/vlan", "interface/bridge/port"]


def validate_host(url, allowed_networks):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("network.https_origin_required")
    permitted = [ipaddress.ip_network(n.strip()) for n in allowed_networks.split(",")]
    addresses = {v[4][0] for v in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not any(ipaddress.ip_address(a) in n for n in permitted) for a in addresses):
        raise ValueError("network.address_not_allowed")
    return url.rstrip("/")


def redact(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() == "key" or any(s in k.lower() for s in ("password", "passphrase", "secret", "private-key", "psk", "pre-shared-key")) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def snapshot_hash(snapshot):
    volatile = {"last-seen", "expires-after", "active-address", "active-mac-address", "active-server", "status", "uptime", "rx-byte", "tx-byte"}
    paths = {p: [{k: v for k, v in row.items() if k not in volatile} for row in rows]
             for p, rows in snapshot.items() if p in ("ip/dhcp-server/lease", "ip/firewall/address-list", "ip/firewall/filter", "ipv6/firewall/filter") or p.endswith("access-list")}
    return digest(canonical(paths))


class RouterOS:
    def __init__(self, base_url, username, password, ca_file=None, transport=None):
        context = ssl.create_default_context(cafile=ca_file)
        self.client = httpx.AsyncClient(base_url=base_url.rstrip("/") + "/rest/", auth=(username, password),
                                        verify=context, timeout=httpx.Timeout(15, connect=5),
                                        follow_redirects=False, transport=transport, trust_env=False)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.client.aclose()

    async def read(self, path, optional=False, properties=None):
        response = await self.client.get(path, params={".proplist": properties} if properties else None)
        if optional and response.status_code in (400, 404):
            try:
                error = response.json()
                message = error.get("message", "") + " " + error.get("detail", "")
            except ValueError:
                message = ""
            if response.status_code == 404 or "no such command" in message:
                return None
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, list) else [data]

    async def command(self, path, data=None):
        if path not in {"system/reboot", "system/backup/save", "system/backup/load", "ping", "interface/monitor-traffic", "file/read"}:
            raise ValueError("network.operation_not_allowed")
        response = await self.client.post(path, json=data or {})
        response.raise_for_status()
        return response.json() if response.content else {}

    async def configure(self, path, record_id, data):
        allowed = {"interface/wifi", "interface/wireless", "caps-man/interface", "system/identity"}
        if path not in allowed or not record_id.startswith("*") or "/" in record_id:
            raise ValueError("network.operation_not_allowed")
        response = await self.client.post("system/identity/set", json=data) if path == "system/identity" else await self.client.patch(path + "/" + record_id, json=data)
        response.raise_for_status()
        return response.json()

    async def discovery(self):
        snapshot = {}
        for path in PATHS:
            snapshot[path] = await self.read(path, optional=path.startswith(("ipv6/", "interface/bridge")))
            if snapshot[path] is None:
                snapshot[path] = []
        capabilities = {"stacks": [], "private_passphrase": "REQUIRES_MODEL_AND_LAB_VALIDATION",
                        "dynamic_vlan": "UNVERIFIED", "l2_isolation": "UNVERIFIED"}
        for stack, (interfaces, acl, registrations) in STACKS.items():
            data = await self.read(interfaces, optional=True)
            if data is not None:
                capabilities["stacks"].append(stack)
                snapshot[interfaces] = data
                snapshot[acl] = await self.read(acl)
                snapshot[registrations] = await self.read(registrations)
        for path in ("system/routerboard", "system/identity", "system/health", "interface/ethernet", "interface/vlan",
                     "interface/wifi/security", "interface/wifi/configuration", "caps-man/configuration", "interface/wireless/security-profiles", "caps-man/security", "caps-man/remote-cap",
                     "interface/wifi/capsman/remote-cap", "log"):
            data = await self.read(path, optional=True)
            snapshot[path] = (data[-100:] if path == "log" and data else data) or []
        capabilities["version"] = snapshot["system/resource"][0].get("version", "unknown")
        capabilities["board"] = snapshot["system/resource"][0].get("board-name", "unknown")
        capabilities["packages"] = [p.get("name") for p in snapshot["system/package"]]
        capabilities["bridge_vlan_filtering"] = any(b.get("vlan-filtering") == "true" for b in snapshot["interface/bridge"])
        return {"capabilities": capabilities, "snapshot": snapshot}

    async def apply(self, operation):
        path, method = operation["path"], operation["method"]
        allowed = {"ip/dhcp-server/lease", "ip/firewall/address-list"} | {v[1] for v in STACKS.values()} | {v[2] for v in STACKS.values()}
        if path not in allowed or method not in ("PUT", "PATCH", "DELETE"):
            raise ValueError("network.operation_not_allowed")
        target = path + ("/" + operation["id"] if operation.get("id") else "")
        if method in ("PATCH", "DELETE") and not operation.get("id"):
            raise ValueError("network.missing_record_id")
        response = await self.client.request(method, target, json=operation.get("data") if method != "DELETE" else None)
        response.raise_for_status()
        return response.json() if response.content else {}
