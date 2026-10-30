"""Compatibility with the pre-Suro "kursant" scripts and their AcademyAdmin password.

The original scripts (PasswordGenerator_*.ps1, kursant_script_*.ps1) derived the local administrator
password from the Wi-Fi adapter MAC address. `legacy_mac_v1` is a line-for-line port of their
`Convert-MacToUniquePassword`; do not "improve" it, or existing machines lose their recovery password.

Anyone who knows this algorithm and a machine's Wi-Fi MAC (which is broadcast over the air) can compute
that password, so new machines use `random_password` instead (see docs/developers/legacy-credentials.md).
"""

import re
import secrets
from urllib.parse import urlsplit
from ipaddress import ip_address

LEGACY_ACCOUNT = "AcademyAdmin"
LEGACY_TASK_PATH = "\\Custom Tasks\\"
LEGACY_TASK_NAME = "Running_kursant_script_at_every_startup"
# The outbound allowlist hardcoded in kursant_persisting_*.ps1, re-applied after a firewall reset at every boot.
LEGACY_ALLOWED_ADDRESSES = ("192.168.0.1", "10.47.47.47", "10.47.47.74")
_SPECIALS = "!@#$%^&*"  # A double-quoted PowerShell string, but "$%" is not a variable, so it stays literal.


def legacy_mac_v1(mac: str) -> str:
    clean = str(mac).replace("-", "").replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{12}", clean):
        raise ValueError("credential.invalid_mac")
    data = bytes.fromhex(clean)
    mixed = []
    for i in range(6):
        mix = data[i]
        for j in range(6):
            if i == j:
                continue
            operation = (i + j) % 4
            if operation == 0:
                mix ^= data[j]
            elif operation == 1:
                mix = (mix + data[j]) & 0xFF
            elif operation == 2:
                mix = (mix | (data[j] << (j % 4))) & 0xFF
            else:
                mix = (mix ^ (data[j] >> (i % 3))) & 0xFF
        mixed.append(mix)
    password = [chr(65 + (mixed[i] * (i + 1) + mixed[5 - i] * (4 - i)) % 26) for i in range(3)]
    password += [str(((mixed[i] ^ mixed[i + 1]) + (mixed[i + 2] & mixed[i + 3])) % 10) for i in range(2)]
    for i in range(3):
        # PowerShell widens [byte] operands to Int32, so the rotation is not truncated to 8 bits before "% 26".
        rotation = (mixed[i] << 3) | (mixed[i] >> 5)
        password.append(chr((65 if rotation & 1 == 0 else 97) + rotation % 26))
    password.append(_SPECIALS[sum(mixed) % len(_SPECIALS)])
    checksum = sum(value * (i + 1) for i, value in enumerate(mixed)) % 36
    password.append(str(checksum) if checksum < 10 else chr(65 + checksum - 10))
    return "".join(password)


def _mac(value):
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2)) if len(raw) == 12 else None


def legacy_mac_candidates(adapters, fallback_mac=None):
    """MACs the legacy script could have used, most likely first.

    The script took the first `Get-NetAdapter` entry with MediaType "Native 802.11" whose description
    did not match "Virtual|Hyper-V", after `Sort-Object Status -Descending` ("Up" before "Disconnected").
    Ties are not reliably ordered in Windows PowerShell, and the adapter may since have been replaced or
    have used a randomized address, so every plausible address is returned for an administrator to try.
    """
    rows = [a for a in adapters or [] if isinstance(a, dict)]
    classified = any("media_type" in a for a in rows)
    wifi = [a for a in rows if not classified or (a.get("media_type") == "Native 802.11"
                                                   and not re.search("Virtual|Hyper-V", str(a.get("description") or ""), re.I))]
    wifi.sort(key=lambda a: str(a.get("status") or "").lower(), reverse=True)
    candidates, seen = [], set()
    for adapter in wifi:
        for source in ("mac", "permanent_mac"):
            mac = _mac(adapter.get(source))
            if mac and mac not in seen:
                seen.add(mac)
                candidates.append({"mac": mac, "adapter": str(adapter.get("name") or "")[:128],
                                   "status": str(adapter.get("status") or ""),
                                   "source": "current" if source == "mac" else "permanent",
                                   "classified": classified})
    fallback = _mac(fallback_mac)
    if fallback and fallback not in seen:
        candidates.append({"mac": fallback, "adapter": "", "status": "", "source": "registered", "classified": False})
    return candidates


def random_password(length=20):
    """Windows complexity rules need three character classes; this always uses all four."""
    classes = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!#%*+-=?@"]
    alphabet = "".join(classes)
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in group for c in value) for group in classes):
            return value


def _server_address(public_origin):
    try:
        return str(ip_address(urlsplit(public_origin).hostname or ""))
    except ValueError:
        return None


def legacy_state(inventory, public_origin):
    """Interpret agent-reported legacy artifacts. Facts only; nothing here changes the endpoint."""
    inventory = inventory or {}
    legacy = inventory.get("legacy") if isinstance(inventory.get("legacy"), dict) else None
    users = [u for u in inventory.get("users") or [] if isinstance(u, dict)]
    admin = next((u for u in users if str(u.get("name", "")).lower() == LEGACY_ACCOUNT.lower()), None)
    result = {
        "reported": legacy is not None,
        "admin_account": {"present": bool(admin), "enabled": bool(admin and admin.get("enabled")),
                          "administrator": bool(admin and admin.get("administrator"))},
        "startup_task": None, "kursant_username": None, "persisting_scripts": [],
        "allowed_addresses": [], "server_address": _server_address(public_origin),
        "server_allowed_after_boot": None, "winre": "UNKNOWN", "findings": [],
    }
    if admin:
        result["findings"].append("legacy.admin_account_present")
    if legacy is None:
        return result
    task = legacy.get("startup_task") if isinstance(legacy.get("startup_task"), dict) else None
    if task:
        result["startup_task"] = {"state": str(task.get("state") or "")[:32]}
        username = task.get("kursant_username")
        result["kursant_username"] = str(username)[:64] if username else None
    result["persisting_scripts"] = [str(s)[:128] for s in legacy.get("persisting_scripts") or []][:10]
    addresses = []
    for value in legacy.get("firewall_rule_addresses") or []:
        for part in str(value).split(","):
            if part.strip():
                addresses.append(part.strip()[:64])
    result["allowed_addresses"] = sorted(set(addresses)) or (list(LEGACY_ALLOWED_ADDRESSES) if task else [])
    resets = bool(task and str(task.get("state", "")).lower() != "disabled")
    if resets:
        result["findings"].append("legacy.firewall_reset_at_boot")
        if result["server_address"]:
            allowed = result["server_address"] in result["allowed_addresses"]
            result["server_allowed_after_boot"] = allowed
            if not allowed:
                result["findings"].append("legacy.server_blocked_after_boot")
        else:
            result["findings"].append("legacy.server_address_unverified")
    state = str(legacy.get("winre_state") or "")
    result["winre"] = {"1": "ENABLED", "0": "DISABLED"}.get(state, "UNKNOWN")
    if result["winre"] == "DISABLED":
        result["findings"].append("legacy.winre_disabled")
    return result
