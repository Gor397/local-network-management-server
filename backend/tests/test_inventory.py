"""Passive inventory merges stored router observations and never contacts routers."""
import json
from app.models import Router, Device, DeviceCredential
from app.db import utcnow
from test_suro import infrastructure_factory  # noqa: F401  (fixture)


def seed(app, identifier):
    with app.state.sessions.begin() as db:
        r = db.get(Router, identifier)
        snapshot = json.loads(app.state.vault.open(r.snapshot))
        snapshot["ip/dhcp-server/lease"] = [
            {".id": "*1", "mac-address": "00:11:22:33:44:55", "address": "192.168.88.30", "host-name": "PILOT-01", "status": "bound", "dynamic": "true"},
            {".id": "*2", "mac-address": "3A:11:22:33:44:66", "address": "192.168.88.31", "host-name": "phone", "status": "bound", "dynamic": "true"},
        ]
        snapshot["ip/arp"] = [
            {"mac-address": "00:11:22:33:44:55", "address": "192.168.88.30", "interface": "bridge"},
            {"mac-address": "00:AA:BB:CC:DD:EE", "address": "192.168.88.31", "interface": "bridge"},
        ]
        snapshot["interface/wifi/registration-table"] = [{"mac-address": "00:11:22:33:44:55", "interface": "wifi1", "ssid": "Office", "signal": "-60"}]
        r.snapshot = app.state.vault.seal(json.dumps(snapshot))
        d = Device(hostname="PILOT-01", primary_mac="00:11:22:33:44:55")
        db.add(d)
        db.flush()
        db.add(DeviceCredential(device_id=d.id, fingerprint="f" * 64, certificate="x", expires_at=utcnow()))
        d.last_heartbeat = utcnow()


def test_inventory_merges_sources_and_flags_inferences(admin, app, infrastructure_factory, monkeypatch):
    import app.services.network as network
    monkeypatch.setattr(network, "connector", lambda *a: (_ for _ in ()).throw(AssertionError("router contacted")))
    seed(app, infrastructure_factory())
    body = admin.get("/api/v1/network/inventory").json()
    rows = {i["mac"]: i for i in body["items"]}
    pilot = rows["00:11:22:33:44:55"]
    assert pilot["sources"] == ["arp", "dhcp_lease", "wifi_registration"] and pilot["enrollment"] == "AGENT_HEALTHY"
    assert pilot["wifi"]["ssid"] == "Office" and pilot["hostnames"] == ["PILOT-01"]
    phone = rows["3A:11:22:33:44:66"]
    assert phone["randomized_mac"] and phone["enrollment"] == "NOT_REGISTERED"
    assert phone["duplicate_address"] == ["192.168.88.31"] and rows["00:AA:BB:CC:DD:EE"]["duplicate_address"] == ["192.168.88.31"]
    assert body["summary"]["NOT_REGISTERED"] == 2
    assert admin.get("/api/v1/network/inventory?enrollment=AGENT_HEALTHY").json()["total"] == 1


def test_label_is_descriptive_and_audited(admin, app, infrastructure_factory):
    seed(app, infrastructure_factory())
    result = admin.put("/api/v1/network/inventory/00-aa-bb-cc-dd-ee/label", json={"category": "PRINTER", "label": "Floor 2 printer"})
    assert result.status_code == 200 and result.json()["mac"] == "00:AA:BB:CC:DD:EE"
    row = next(i for i in admin.get("/api/v1/network/inventory?q=floor").json()["items"])
    # A label never changes enrollment or admission state.
    assert row["category"] == "PRINTER" and row["enrollment"] == "NOT_REGISTERED"
    assert admin.put("/api/v1/network/inventory/not-a-mac/label", json={}).status_code == 422
    assert admin.put("/api/v1/network/inventory/00:aa:bb:cc:dd:ee/label", json={"category": "TRUSTED"}).status_code == 422
    assert any(e["action"] == "network.endpoint_labelled" for e in admin.get("/api/v1/audit").json())
