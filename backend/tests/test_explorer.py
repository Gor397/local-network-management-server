"""Network Explorer keeps registry, Wi-Fi association, agent heartbeat and compliance separate."""
from datetime import timedelta
from app.db import utcnow
from app.models import Device, DeviceGroup, GroupMember, Router, RouterTelemetry
from tests.test_capsman import SNAPSHOT, controller  # noqa: F401  (fixture)


def _devices(app, controller_id):
    now = utcnow()
    with app.state.sessions.begin() as db:
        group = DeviceGroup(name="Room 5")
        db.add(group)
        # On Wi-Fi now and reporting through its agent.
        both = Device(hostname="PC-BOTH", primary_mac="A8:3B:76:00:00:01", state="COMPLIANT", last_heartbeat=now,
                      last_verified=now, compliance_score=100)
        # Agent reports, but no AP lists it (wired, or on an AP Suro does not poll).
        agent_only = Device(hostname="PC-WIRED", primary_mac="A8:3B:76:00:00:03", state="NONCOMPLIANT", mode="AUDIT",
                            last_heartbeat=now)
        # Seen before on Floor-2 but the controller's fresh poll no longer lists it, and the agent is silent.
        gone = Device(hostname="PC-GONE", primary_mac="A8:3B:76:00:00:04", state="UNVERIFIED",
                      last_heartbeat=now - timedelta(hours=3),
                      network_evidence={"router_id": controller_id, "ap": "Floor-2", "connected": False,
                                        "observed_at": now.isoformat()})
        never = Device(hostname="PC-NEW", primary_mac="A8:3B:76:00:00:05")
        db.add_all([both, agent_only, gone, never])
        db.flush()
        db.add(GroupMember(group_id=group.id, device_id=both.id))
        return {d.hostname: d.id for d in (both, agent_only, gone, never)}


def test_explorer_statuses_have_independent_sources(admin, app, controller):  # noqa: F811
    ids = _devices(app, controller)
    data = admin.get("/api/v1/network/explorer").json()
    rows = {d["hostname"]: d for d in data["devices"]}
    aps = {a["name"]: a for a in data["access_points"]}
    assert aps["Gateway"]["kind"] == "controller" and aps["Hall-1"]["kind"] == "access_point"
    # Attributed to the CAP that carries the radio, not to the controller that reported it.
    assert rows["PC-BOTH"]["wifi"] == "ASSOCIATED" and rows["PC-BOTH"]["ap_id"] == aps["Hall-1"]["id"]
    assert aps["Hall-1"]["registered_now"] == [ids["PC-BOTH"]] and aps["Hall-1"]["unregistered_now"] == 1
    assert rows["PC-BOTH"]["agent"] == "ONLINE" and rows["PC-BOTH"]["compliance"] == "COMPLIANT"
    # Agent online is not network online: no AP lists it, which is unknown rather than offline.
    assert rows["PC-WIRED"]["agent"] == "ONLINE" and rows["PC-WIRED"]["wifi"] == "UNKNOWN"
    assert rows["PC-WIRED"]["awaiting_enforcement"] is True
    assert rows["PC-GONE"]["wifi"] == "NOT_ASSOCIATED" and rows["PC-GONE"]["agent"] == "STALE"
    assert ids["PC-GONE"] in aps["Hall-1"]["previously_seen"]
    # Registered is not online: never observed by any source.
    assert rows["PC-NEW"]["never_seen"] is True and rows["PC-NEW"]["agent"] == "NEVER"
    assert rows["PC-BOTH"]["groups"] and not rows["PC-NEW"]["groups"]
    c = data["counts"]
    assert (c["registered"], c["wifi_associated"], c["agent_online"], c["never_seen"], c["offline"], c["ungrouped"]) == (4, 1, 2, 1, 1, 3)


def test_stale_association_sample_is_not_presented_as_connected(admin, app, controller):  # noqa: F811
    _devices(app, controller)
    with app.state.sessions.begin() as db:
        for sample in db.query(RouterTelemetry):
            sample.created_at = utcnow() - timedelta(minutes=30)
        evidence = db.query(Device).filter_by(hostname="PC-GONE").one()
        evidence.network_evidence = {**evidence.network_evidence, "observed_at": (utcnow() - timedelta(hours=1)).isoformat()}
    data = admin.get("/api/v1/network/explorer").json()
    rows = {d["hostname"]: d for d in data["devices"]}
    assert rows["PC-BOTH"]["wifi"] == "UNKNOWN" and rows["PC-GONE"]["wifi"] == "UNKNOWN"
    assert all(not a["registered_now"] for a in data["access_points"])


def test_explorer_requires_login(client):
    assert client.get("/api/v1/network/explorer").status_code == 401
    with client.app.state.sessions() as db:
        assert db.query(Router).count() == 0
