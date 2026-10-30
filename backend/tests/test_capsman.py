"""CAPsMAN access points become inventory rows observed only through their controller."""
import json
import pytest
from app.db import utcnow
from app.models import Router, RouterTelemetry, ApGroupMember
from app.services import capsman
from app.services.safety import router_write_block
from app.config import Settings

SNAPSHOT = {
    "caps-man/remote-cap": [
        {"identity": "Hall-1", "base-mac": "48:A9:8A:00:00:10", "board": "RBcAPGi-5acD2nD", "version": "6.49.7", "state": "Run", "radios": "2"},
        {"identity": "Hall-2", "base-mac": "48:A9:8A:00:00:20", "board": "RBcAPGi-5acD2nD", "version": "6.49.7", "state": "Join", "radios": "1"},
    ],
    # Radio names do not reliably follow the identity; MACs do.
    "caps-man/interface": [
        {"name": "Floor-1", "radio-mac": "48:A9:8A:00:00:11"},
        {"name": "Floor-2", "radio-mac": "48:A9:8A:00:00:12"},
        {"name": "Other-1", "radio-mac": "48:A9:8A:00:00:21"},
        {"name": "Gone-1", "radio-mac": "11:22:33:44:55:66"},
    ],
    "caps-man/registration-table": [
        {"mac-address": "A8:3B:76:00:00:01", "interface": "Floor-1", "ssid": "Office", "comment": "Owner label", "rx-signal": "-50"},
        {"mac-address": "A8:3B:76:00:00:02", "interface": "Floor-2", "ssid": "Office", "rx-signal": "-60"},
    ],
    "ip/dhcp-server/lease": [
        {"mac-address": "A8:3B:76:00:00:01", "address": "192.168.10.5", "host-name": "LAPTOP-01", "status": "bound"},
        {"mac-address": "48:A9:8A:00:00:10", "address": "192.168.0.50", "host-name": "Hall-1", "status": "bound"},
    ],
}


def test_radio_map_uses_mac_proximity_not_names():
    assert capsman.radio_map(SNAPSHOT) == {"Floor-1": "48:A9:8A:00:00:10", "Floor-2": "48:A9:8A:00:00:10",
                                           "Other-1": "48:A9:8A:00:00:20"}


@pytest.fixture
def controller(app):
    with app.state.sessions.begin() as db:
        r = Router(name="Gateway", base_url="https://192.168.88.1:8728", username="reader", secret=app.state.vault.seal("x"),
                   transport="API", role="GATEWAY", capabilities={"stacks": ["capsman"]},
                   snapshot=app.state.vault.seal(json.dumps(SNAPSHOT)), status="ONLINE", last_seen=utcnow())
        db.add(r)
        db.flush()
        capsman.sync_caps(app, db, r, capsman.remote_caps(SNAPSHOT), capsman.radio_map(SNAPSHOT),
                          SNAPSHOT["caps-man/registration-table"], utcnow())
        r.capabilities = {**r.capabilities, "cap_radios": capsman.radio_map(SNAPSHOT)}
        db.add(RouterTelemetry(router_id=r.id, metrics={}, clients=SNAPSHOT["caps-man/registration-table"], facts=[]))
        return r.id


def test_caps_are_listed_groupable_and_never_contacted(admin, app, controller):
    rows = {r["name"]: r for r in admin.get("/api/v1/mikrotik/routers").json()}
    hall = rows["Hall-1"]
    assert hall["controller_name"] == "Gateway" and hall["status"] == "ONLINE" and hall["health"]["client_count"] == 2
    assert hall["inventory"]["model"] == "RBcAPGi-5acD2nD" and rows["Hall-2"]["status"] == "OFFLINE"
    assert admin.post(f"/api/v1/mikrotik/routers/{hall['id']}/discover").json()["error"]["code"] == "router.managed_by_controller"
    with app.state.sessions() as db:
        cap = db.get(Router, hall["id"])
        assert router_write_block(Settings(encryption_key="x", operation_mode="production"), cap) == "router.managed_by_controller"
    group = admin.post("/api/v1/mikrotik/groups", json={"name": "Hall", "router_ids": [hall["id"]]})
    assert group.status_code in (200, 201), group.text
    clients = admin.get(f"/api/v1/network/clients?group_id={group.json()['id']}").json()["items"]
    assert [(c["access_point"], c["hostname"], c["label"]) for c in clients] == [
        ("Hall-1", "LAPTOP-01", "Owner label"), ("Hall-1", None, "")]


def test_unreported_cap_is_kept_and_deleting_controller_removes_its_caps(admin, app, controller):
    with app.state.sessions.begin() as db:
        r = db.get(Router, controller)
        capsman.sync_caps(app, db, r, capsman.remote_caps(SNAPSHOT)[:1], {}, [], utcnow())
    rows = {r["name"]: r for r in admin.get("/api/v1/mikrotik/routers").json()}
    assert rows["Hall-2"]["status"] == "UNAVAILABLE"
    hall = rows["Hall-1"]["id"]
    with app.state.sessions.begin() as db:
        group_id = admin.post("/api/v1/mikrotik/groups", json={"name": "G", "router_ids": [hall]}).json()["id"]
    assert admin.delete(f"/api/v1/mikrotik/routers/{controller}/permanent?confirm_name=Gateway").json()["deleted"]
    with app.state.sessions() as db:
        assert db.query(Router).count() == 0 and db.query(ApGroupMember).count() == 0


def test_inventory_puts_end_devices_first_with_ap_and_label(admin, app, controller):
    items = admin.get("/api/v1/network/inventory").json()["items"]
    laptop = items[0]
    assert laptop["mac"] == "A8:3B:76:00:00:01" and laptop["wifi"]["access_point"] == "Hall-1" and laptop["label"] == "Owner label"
    assert items[-1]["category"] == "INFRASTRUCTURE" and items[-1]["mikrotik_router"] == "Hall-1"
