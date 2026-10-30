"""Archiving hides a router; permanent deletion removes Suro's records only when Suro never changed that router."""
from app.models import Router, RouterTelemetry, AccessPoint, NetworkAccessRule, Device
from test_suro import infrastructure_factory  # noqa: F401  (fixture)


def test_archive_then_permanent_delete_allows_registering_the_same_address(admin, app, infrastructure_factory):
    identifier = infrastructure_factory("Old AP")
    with app.state.sessions.begin() as db:
        base_url = db.get(Router, identifier).base_url
        db.add(RouterTelemetry(router_id=identifier, metrics={}, clients=[], facts=[]))
        db.add(AccessPoint(router_id=identifier, interface_name="cap1", stack="capsman", details={}))
    assert admin.delete(f"/api/v1/mikrotik/routers/{identifier}").json()["archived"]
    assert [r["name"] for r in admin.get("/api/v1/mikrotik/routers/archived").json()] == ["Old AP"]
    body = {"name": "Old AP", "base_url": base_url, "username": "reader", "password": "x"}
    assert admin.post("/api/v1/mikrotik/routers", json=body).json()["error"]["code"] == "router.archived_duplicate"
    wrong = admin.delete(f"/api/v1/mikrotik/routers/{identifier}/permanent?confirm_name=Old")
    assert wrong.json()["error"]["code"] == "router.confirm_name_mismatch"
    assert admin.delete(f"/api/v1/mikrotik/routers/{identifier}/permanent?confirm_name=Old%20AP").json()["deleted"]
    with app.state.sessions() as db:
        assert db.get(Router, identifier) is None
    assert admin.get("/api/v1/mikrotik/routers/archived").json() == []
    assert any(e["action"] == "router.deleted_permanently" for e in admin.get("/api/v1/audit").json())


def test_router_with_suro_owned_changes_cannot_be_deleted(admin, app, infrastructure_factory):
    identifier = infrastructure_factory("Managed AP")
    with app.state.sessions.begin() as db:
        d = Device(hostname="PC", primary_mac="00:11:22:33:44:55")
        db.add(d)
        db.flush()
        db.add(NetworkAccessRule(device_id=d.id, router_id=identifier, owner_tag="lantern:x", rule={}))
    result = admin.delete(f"/api/v1/mikrotik/routers/{identifier}/permanent?confirm_name=Managed%20AP")
    assert result.status_code == 409 and result.json()["error"]["code"] == "router.has_managed_changes"


def test_registration_trims_pasted_whitespace(admin, app):
    body = {"name": " Edge ", "base_url": " https://192.168.88.9 ", "username": " reader ", "password": " keep spaces "}
    identifier = admin.post("/api/v1/mikrotik/routers", json=body).json()["id"]
    with app.state.sessions() as db:
        r = db.get(Router, identifier)
        assert (r.name, r.base_url, r.username) == ("Edge", "https://192.168.88.9", "reader")
        assert app.state.vault.open(r.secret) == " keep spaces "
