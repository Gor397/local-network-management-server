"""Visual policy editor: catalog, drafts, validation, preview, publication, assignment and compliance."""
import base64
import json
from app.models import Device, DeviceGroup, GroupMember, Policy
from app.compliance.engine import not_required
from app.policies.catalog import SETTINGS, AGENT_V1_KEYS, agent_document, diff, server_checks, templates
from app.policies.schema import PolicyDocument
from test_agent_protocol import enrolled, signed_request  # noqa: F401  (fixture)

API = "/api/v1/policies"


def test_every_stored_setting_maps_to_a_real_document_field():
    fields = set(PolicyDocument.model_fields)
    for s in SETTINGS:
        if s["control"] in ("protected", "unavailable"):
            continue
        assert s["key"] in fields, s["id"]
    # Every field an administrator can change has a visual control, except the expert-only weights.
    covered = {s["key"] for s in SETTINGS}
    assert fields - covered == {"schema_version", "weights", "static_ip_address"}
    # Old agents accept only the v1 keys, so everything else must be gated by a feature.
    assert set(agent_document(PolicyDocument().model_dump(), [])) <= AGENT_V1_KEYS


def test_management_server_must_stay_reachable_when_internet_is_blocked():
    document = PolicyDocument().model_dump()
    errors, _ = server_checks(document, "https://192.168.88.10:8443")
    assert errors[0]["code"] == "policy.management_not_allowed"
    assert errors[0]["fix"] == {"remote": "192.168.88.10/32", "protocol": "TCP", "ports": [8443]}
    document["firewall_allowances"] = [errors[0]["fix"]]
    assert server_checks(document, "https://192.168.88.10:8443")[0] == []
    # Templates already include it, and allowing the internet removes the requirement.
    assert server_checks(templates("https://192.168.88.10:8443")["standard"], "https://192.168.88.10:8443")[0] == []
    assert server_checks({**PolicyDocument().model_dump(), "block_internet": False}, "https://192.168.88.10:8443")[0] == []


def test_settings_switch_off_only_their_own_checks():
    base = PolicyDocument()
    assert "network.internet_restriction.valid" not in not_required(base)
    assert "endpoint.ip_configuration.valid" in not_required(base)
    relaxed = PolicyDocument(block_internet=False, require_standard_user=False, ip_mode="dhcp")
    assert {"network.internet_restriction.valid", "account.user.not_administrator"} <= not_required(relaxed)
    assert "endpoint.ip_configuration.valid" not in not_required(relaxed)
    changes = {c["key"]: c for c in diff(base.model_dump(), relaxed.model_dump())}
    assert changes["block_internet"]["risk"] == "network" and changes["require_standard_user"]["risk"] == "safe"


def test_draft_validate_preview_publish_and_restore(admin):
    created = admin.post(API, json={"name": "Classrooms", "description": "Lab PCs", "template": "standard"})
    assert created.status_code == 201
    pid = created.json()["id"]
    policy = admin.get(f"{API}/{pid}").json()
    assert policy["draft"]["auto_remediate"] == ["firewall.enable"] and policy["active_version_id"] is None
    draft = {**policy["draft"], "ip_mode": "static", "ip_prefix": "192.168.10.0/24", "ip_gateway": "10.0.0.1"}
    bad = admin.put(f"{API}/{pid}/draft", json={"document": draft})
    assert bad.status_code == 422 and bad.json()["error"]["fields"][0]["code"] == "policy.gateway_outside_prefix"
    check = admin.post(f"{API}/validate", json={"document": {**draft, "user_account": "bad name"}}).json()
    assert check["valid"] is False and check["errors"][0]["field"] == "user_account"
    draft["ip_gateway"] = "192.168.10.1"
    saved = admin.put(f"{API}/{pid}/draft", json={"document": draft})
    assert saved.status_code == 200, saved.text
    stale = admin.put(f"{API}/{pid}/draft", json={"document": draft, "expected_draft_at": "2020-01-01T00:00:00"})
    assert stale.json()["error"]["code"] == "policy.draft_changed"
    assert admin.delete(f"{API}/{pid}/draft").json()["error"]["code"] == "policy.draft_is_only_copy"
    preview = admin.post(f"{API}/{pid}/preview", json={}).json()
    assert preview["first_version"] is True and preview["affected"]["devices"] == 0
    assert {c["key"] for c in preview["changes"]} >= {"ip_mode", "ip_prefix", "ip_gateway"}
    published = admin.post(f"{API}/{pid}/publish", json={"reason": "first release"})
    assert published.status_code == 200, published.text
    first = published.json()["id"]
    detail = admin.get(f"{API}/{pid}").json()
    assert detail["draft"] is None and detail["active_version_id"] == first and detail["versions"][0]["author"] == "owner"
    assert admin.post(f"{API}/{pid}/publish", json={"reason": "nothing new", "expected_version_id": first}).json()["error"]["code"] == "policy.nothing_to_publish"
    # Change, publish a second version, then compare and restore the first into a draft.
    admin.put(f"{API}/{pid}/draft", json={"document": {**draft, "hide_c": True}})
    second = admin.post(f"{API}/{pid}/publish", json={"reason": "hide C", "expected_version_id": first}).json()["id"]
    changes = admin.get(f"{API}/{pid}/diff", params={"base": first, "target": second}).json()["changes"]
    assert [(c["key"], c["before"], c["after"]) for c in changes] == [("hide_c", False, True)]
    admin.post(f"{API}/{pid}/restore", json={"version_id": first})
    assert admin.get(f"{API}/{pid}").json()["draft"]["hide_c"] is False
    assert admin.get(f"{API}/{pid}").json()["active_version_id"] == second
    listed = next(p for p in admin.get(API).json() if p["id"] == pid)
    assert listed["has_draft"] and listed["active_sequence"] == 2


def test_assignment_preview_and_group_targets(admin, app):
    pid = admin.post(API, json={"name": "Groups", "template": "custom"}).json()["id"]
    assert admin.post(f"{API}/{pid}/assign-targets", json={"all_devices": True, "reason": "too early"}).json()["error"]["code"] == "policy.not_published"
    admin.post(f"{API}/{pid}/publish", json={"reason": "release"})
    ids = [admin.post("/api/v1/devices", json={"hostname": f"PC-{i}", "primary_mac": f"00:11:22:33:44:5{i}"}).json()["id"] for i in range(3)]
    admin.post("/api/v1/devices", json={"hostname": "DEV", "primary_mac": "00:11:22:33:44:60", "device_class": "DEVELOPER"})
    with app.state.sessions.begin() as db:
        group = DeviceGroup(name="Room 1")
        db.add(group)
        db.flush()
        db.add_all([GroupMember(group_id=group.id, device_id=i) for i in ids[:2]])
        group_id = group.id
    preview = admin.post(f"{API}/{pid}/assignment-preview", json={"group_ids": [group_id], "device_ids": [ids[2]]}).json()
    assert (preview["total"], preview["offline"], preview["never_seen"], preview["already"]) == (3, 3, 3, 0)
    assert admin.post(f"{API}/{pid}/assignment-preview", json={"all_devices": True}).json()["total"] == 3  # developer excluded
    assigned = admin.post(f"{API}/{pid}/assign-targets", json={"group_ids": [group_id], "reason": "room rollout"})
    assert assigned.json() == {"assigned": 2}
    report = admin.get(f"{API}/{pid}/compliance").json()
    assert report["counts"]["total"] == 2 and report["counts"]["not_reported"] == 2 and report["counts"]["compliant"] == 0
    assert admin.post(f"{API}/{pid}/assignment-preview", json={"group_ids": [group_id]}).json()["already"] == 2


def test_agents_receive_only_settings_they_understand(admin, app, enrolled):
    d, key, fingerprint, _ = enrolled
    with app.state.sessions.begin() as db:
        pid = db.query(Policy).one().id
    document = {**PolicyDocument().model_dump(), "min_d_gb": 100, "ip_mode": "dhcp"}
    admin.post(f"{API}/{pid}/publish", json={"document": document, "reason": "new settings",
                                               "expected_version_id": admin.get(f"{API}/{pid}").json()["active_version_id"]})

    def delivered():
        envelope = signed_request(admin, key, fingerprint, "GET", "/api/v1/agent/policy").json()
        return json.loads(base64.b64decode(envelope["payload"]))["document"]
    old = delivered()
    assert "min_d_gb" not in old and "ip_mode" not in old and set(old) <= AGENT_V1_KEYS
    beat = {"agent_version": "0.2.0", "os_version": "10", "policy_features": ["min_d_gb", "ip_mode", "bogus"]}
    assert signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat", beat).status_code == 200
    new = delivered()
    assert new["min_d_gb"] == 100 and new["ip_mode"] == "dhcp" and "block_internet" not in new
    with app.state.sessions() as db:
        assert db.get(Device, d["id"]).agent_features == ["ip_mode", "min_d_gb"]


def test_policy_can_switch_off_software_deployment(admin, app, enrolled):
    from test_deployments import upload_package
    d, *_ = enrolled
    with app.state.sessions.begin() as db:
        pid = db.query(Policy).one().id
    active = admin.get(f"{API}/{pid}").json()["active_version_id"]
    admin.post(f"{API}/{pid}/publish", json={"document": {**PolicyDocument().model_dump(), "allow_software_deployment": False},
                                               "reason": "no installs", "expected_version_id": active})
    package = upload_package(admin).json()["package_id"]
    admin.post(f"/api/v1/packages/{package}/approve", json={"reason": "approved test package"})
    app.state.settings.deployment_enabled = True
    refused = admin.post("/api/v1/deployments", json={"package_id": package, "device_ids": [d["id"]], "reason": "try install"})
    assert refused.json()["error"]["code"] == "deployment.disabled_by_policy"


def test_relaxing_layers_and_duplicate_static_addresses_are_refused(admin, app):
    pid = admin.post(API, json={"name": "Static", "template": "custom"}).json()["id"]
    draft = {**admin.get(f"{API}/{pid}").json()["draft"], "ip_mode": "static", "ip_prefix": "192.168.20.0/24"}
    admin.put(f"{API}/{pid}/draft", json={"document": draft})
    admin.post(f"{API}/{pid}/publish", json={"reason": "static network"})
    a, b = (admin.post("/api/v1/devices", json={"hostname": n, "primary_mac": m}).json()["id"]
            for n, m in (("A", "00:11:22:33:44:71"), ("B", "00:11:22:33:44:72")))
    layer = {"scope": "DEVICE", "controls": {"static_ip_address": "192.168.20.15"}, "reason": "fixed address"}
    assert admin.post(f"{API}/{pid}/layers", json={**layer, "target": a}).status_code == 200
    assert admin.post(f"{API}/{pid}/layers", json={**layer, "target": b}).json()["error"]["code"] == "policy.duplicate_static_address"
    outside = {**layer, "target": b, "controls": {"static_ip_address": "10.9.9.9"}}
    assert admin.post(f"{API}/{pid}/layers", json=outside).status_code == 422
    weaker = {"scope": "DEVICE", "target": b, "controls": {"block_internet": False}, "reason": "needs internet"}
    assert "relaxation_requires_approval" in admin.post(f"{API}/{pid}/layers", json=weaker).json()["error"]["code"]
    group_wide = {"scope": "GLOBAL", "controls": {"static_ip_address": "192.168.20.16"}, "reason": "shared address"}
    assert admin.post(f"{API}/{pid}/layers", json=group_wide).json()["error"]["code"] == "policy.static_address_device_only"


def test_dashboard_fixture_matches_the_server_catalog(admin):
    """The dashboard tests render from this file; regenerate it when the catalog changes (docs/developers/policy-editor.md)."""
    from pathlib import Path
    fixture = json.loads((Path(__file__).parents[2] / "frontend/tests/fixtures/policy-catalog.json").read_text())
    served = admin.get(f"{API}/catalog").json()
    for key in ("categories", "settings", "checks", "default"):
        assert fixture[key] == served[key], key


def test_publishing_a_version_that_breaks_a_computer_layer_names_the_computer(admin):
    pid = admin.post(API, json={"name": "Layered", "template": "custom"}).json()["id"]
    draft = {**admin.get(f"{API}/{pid}").json()["draft"], "ip_mode": "static", "ip_prefix": "192.168.30.0/24"}
    admin.put(f"{API}/{pid}/draft", json={"document": draft})
    first = admin.post(f"{API}/{pid}/publish", json={"reason": "static"}).json()["id"]
    device = admin.post("/api/v1/devices", json={"hostname": "PC-L", "primary_mac": "00:11:22:33:44:81"}).json()["id"]
    admin.post(f"{API}/{pid}/layers", json={"scope": "DEVICE", "target": device, "controls": {"static_ip_address": "192.168.30.9"}, "reason": "fixed"})
    admin.post(f"{API}/{pid}/assign-targets", json={"device_ids": [device], "reason": "assign it"})
    admin.put(f"{API}/{pid}/draft", json={"document": {**draft, "ip_mode": "dhcp", "ip_prefix": None}})
    error = admin.post(f"{API}/{pid}/publish", json={"reason": "back to dhcp", "expected_version_id": first}).json()["error"]
    assert error == {"code": "policy.layer_incompatible", "device": "PC-L", "reason": "policy.static_fields_without_static_mode"}
