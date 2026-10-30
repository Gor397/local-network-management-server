"""CAPsMAN access points as first-class inventory, observed only through their controller.

A CAP row is a Router with transport CAPSMAN and controller_id set. Suro never connects to it, never
writes to it, and never deletes it automatically when the controller stops reporting it.
"""
from sqlalchemy import select
from app.models import Router

REMOTE_CAP_PATHS = ("caps-man/remote-cap", "interface/wifi/capsman/remote-cap")
RADIO_PATHS = ("caps-man/interface",)
REGISTRATION_PATHS = ("caps-man/registration-table",)
# A CAP's radio MACs follow its base MAC; observed offsets are 1-2, allow a few spare.
MAX_RADIO_OFFSET = 8


def _mac(value):
    try:
        return int((value or "").replace(":", ""), 16)
    except ValueError:
        return None


def remote_caps(snapshot):
    return [c for path in REMOTE_CAP_PATHS for c in snapshot.get(path, []) if c.get("base-mac")]


def radio_map(snapshot):
    """{radio interface name: CAP base MAC} using the radio MAC closest above a CAP base MAC."""
    bases = sorted((_mac(c["base-mac"]), c["base-mac"].upper()) for c in remote_caps(snapshot))
    found = {}
    for radio in (r for path in RADIO_PATHS for r in snapshot.get(path, [])):
        value = _mac(radio.get("radio-mac") or radio.get("mac-address"))
        if value is None:
            continue
        owner = None
        for base, mac in bases:
            if 0 <= value - base <= MAX_RADIO_OFFSET:
                owner = mac
        if owner:
            found[radio["name"]] = owner
    return found


def cap_url(controller, base_mac):
    return f"capsman://{controller.id}/{base_mac.upper()}"


def sync_caps(app, db, controller, caps, radios, clients, now):
    """Create/update CAP rows from remote-cap rows. radios: {interface: base MAC}; clients: registrations."""
    counts = {}
    for client in clients:
        owner = radios.get(client.get("interface"))
        if owner:
            counts[owner] = counts.get(owner, 0) + 1
    existing = {r.base_url: r for r in db.scalars(select(Router).where(Router.controller_id == controller.id))}
    seen = set()
    for cap in caps:
        base = cap["base-mac"].upper()
        url = cap_url(controller, base)
        seen.add(url)
        row = existing.get(url)
        if not row:
            name = cap.get("identity") or base
            if db.scalar(select(Router.id).where(Router.name == name)):
                name = f"{name} ({base})"
            row = Router(name=name, base_url=url, username="", secret=app.state.vault.seal(""), transport="CAPSMAN",
                         role="ACCESS_POINT", controller_id=controller.id, write_enabled=False)
            db.add(row)
        if row.archived:
            continue
        running = cap.get("state") == "Run"
        row.inventory = {**(row.inventory or {}), "model": cap.get("board"), "version": cap.get("version"),
                         "serial_number": cap.get("serial"), "identity": cap.get("identity"), "base_mac": base,
                         "address": cap.get("address"), "radios": cap.get("radios"), "controller": controller.name}
        row.health = {"reachable": running, "state": cap.get("state"), "client_count": counts.get(base, 0),
                      "observed_at": now.isoformat(), "source": "capsman_controller"}
        row.status = "ONLINE" if running else "OFFLINE"
        row.last_health = row.last_inventory = now
        if running:
            row.last_seen = now
    for url, row in existing.items():
        if url not in seen and not row.archived:
            # Not reported any more: it may be powered off or moved. Keep the record.
            row.status, row.health = "UNAVAILABLE", {**(row.health or {}), "reachable": False, "state": "NOT_REPORTED",
                                                     "client_count": 0, "observed_at": now.isoformat()}


def mark_unknown(db, controller, now):
    """The controller could not be reached, so nothing is known about its CAPs."""
    for row in db.scalars(select(Router).where(Router.controller_id == controller.id, Router.archived.is_(False))):
        row.status = "UNKNOWN"
        row.health = {**(row.health or {}), "reachable": None, "observed_at": now.isoformat()}
