"""Who must run the Suro Client: one computer, a chosen list, or every computer of a subnet except exceptions.

All router traffic goes to the in-memory FakeRouterOS through GuardedRouter, as in test_client_admission.py.
"""
import hashlib
import json
import struct
import pytest
from sqlalchemy import select
from app.models import Administrator, AdmissionSubnet, Device, Enrollment, NetworkAdmission, SoftwarePackage
from app.services.safety import firewall_shape
from test_agent_protocol import enrolled, signed_request  # noqa: F401  (fixture)
from test_client_admission import MAC, PEER, SERVER, base_snapshot, csr, router_env, run_worker  # noqa: F401  (fixture)
from test_foundation import create_device

STRANGER = "AA:00:00:00:00:03"  # a computer Suro has never seen


def set_mode(admin, mode):
    current = admin.get("/api/v1/admission/policy").json()
    body = {k: v for k, v in current.items() if k not in ("group_ids", "updated_at")}
    return admin.put("/api/v1/admission/policy", json={**body, "mode": mode, "reason": f"switch to {mode}"})


def addresses(tables, path="ip/firewall/address-list"):
    return [r for r in tables[path] if r.get("list") == "suro-admitted"]


def test_selected_computers_share_one_reviewed_router_plan(admin, app, router_env, enrolled):
    d, *_ = enrolled
    other = create_device(admin, mac=PEER)
    developer = create_device(admin, mac="00:11:22:33:44:66", cls="DEVELOPER")
    assert set_mode(admin, "PILOT").json()["mode"] == "PILOT"
    added = admin.post("/api/v1/admission/selected", json={"device_ids": [d["id"], other["id"], developer["id"], "missing"],
                                                          "router_id": router_env.router_id, "reason": "two laptops"}).json()
    assert added["added"] == [d["id"], other["id"]]
    assert {s["code"] for s in added["skipped"]} == {"admission.device_exempt", "device.not_found"}
    assert router_env.fake.writes == []  # choosing computers never touches the router
    preview = admin.post(f"/api/v1/admission/routers/{router_env.router_id}/gate-preview", json={"reason": "gate both"}).json()
    assert {i["device_id"] for i in preview["included"]} == {d["id"], other["id"]} and preview["skipped"] == []
    done = admin.post(f"/api/v1/admission/routers/{router_env.router_id}/apply", json={"plan_id": preview["plan"]["id"], "reason": "gate both"})
    assert done.json() == {"state": "VERIFIED", "devices": 2}, done.text
    rules = router_env.fake.tables["ip/firewall/filter"]
    assert [r["comment"] for r in rules][-2:] == ["defconf", "defconf"]
    assert {r.get("src-mac-address") for r in rules[:-2]} == {MAC, PEER}
    with app.state.sessions() as db:
        assert {a.gate_state for a in db.scalars(select(NetworkAdmission))} == {"INSTALLED"}
    again = admin.post(f"/api/v1/admission/routers/{router_env.router_id}/gate-preview", json={"reason": "gate both"})
    assert again.json()["error"]["code"] == "admission.nothing_to_prepare"


async def test_all_computers_except_exceptions_on_a_subnet(admin, client, app, router_env, enrolled):
    d, key, fingerprint, _ = enrolled
    tables = router_env.fake.tables
    tables["ip/arp"].append({".id": "*A3", "address": "192.168.88.52", "mac-address": STRANGER})
    assert admin.post("/api/v1/admission/subnets", json={"router_id": router_env.router_id, "cidr": "192.168.88.0/24",
                                                         "reason": "whole floor"}).json()["error"]["code"] == "admission.mode_not_all"
    assert set_mode(admin, "ALL").json()["mode"] == "ALL"
    printer = admin.post("/api/v1/admission/exceptions", json={"mac": PEER, "name": "Printer", "device_class": "OTHER",
                                                               "reason": "network printer"})
    assert printer.status_code == 201 and printer.json()["exempt"]
    for bad in ("10.0.0.0/8", "fe80::/64", "nonsense"):
        assert admin.post("/api/v1/admission/subnets", json={"router_id": router_env.router_id, "cidr": bad,
                                                             "reason": "whole floor"}).status_code == 422
    subnet = admin.post("/api/v1/admission/subnets", json={"router_id": router_env.router_id, "cidr": "192.168.88.0/24",
                                                           "reason": "whole floor"}).json()
    assert subnet["state"] == "PREPARING"
    assert admin.post("/api/v1/admission/subnets", json={"router_id": router_env.router_id, "cidr": "192.168.88.128/25",
                                                         "reason": "overlap"}).json()["error"]["code"] == "admission.subnet_overlaps"
    # Preparing: the worker brings known computers in the subnet under per-computer grants; nothing is dropped yet.
    await run_worker(app)
    signed_request(admin, key, fingerprint, "POST", "/api/v1/agent/heartbeat",
                   {"agent_version": "0.4.0", "os_version": "10", "health": {"ip": "192.168.88.50"}})
    await run_worker(app)
    assert {r["address"]: "timeout" in r for r in addresses(tables)} == {"192.168.88.50": True, "192.168.88.51": False}
    assert [r["comment"] for r in tables["ip/firewall/filter"]] == ["defconf", "defconf"]
    row = next(r for r in admin.get("/api/v1/admission/overview").json()["items"] if r["device_id"] == d["id"])
    assert row["network"] == "AUTHORIZED" and row["source"] == "ALL"
    # Preview names every host that would lose access; the administrator must confirm that count.
    preview = admin.post(f"/api/v1/admission/subnets/{subnet['id']}/preview", json={"reason": "enforce floor"}).json()
    report = preview["feasibility"]
    assert report["blockers"] == [] and [h["address"] for h in report["restricted"]] == ["192.168.88.52"]
    assert {"admission.subnet_hosts_restricted", "admission.subnet_ipv6_not_gated"} <= set(report["warnings"])
    assert preview["plan"]["confirm_restricted"] == 1
    wrong = admin.post(f"/api/v1/admission/subnets/{subnet['id']}/apply",
                       json={"plan_id": preview["plan"]["id"], "reason": "enforce floor", "confirm_restricted": 0})
    assert wrong.json()["error"]["code"] == "admission.confirm_restricted_mismatch" and len(tables["ip/firewall/filter"]) == 2
    done = admin.post(f"/api/v1/admission/subnets/{subnet['id']}/apply",
                      json={"plan_id": preview["plan"]["id"], "reason": "enforce floor", "confirm_restricted": 1})
    assert done.json()["state"] == "VERIFIED", done.text
    rules = tables["ip/firewall/filter"]
    assert [r.get("src-address") for r in rules[:2]] == ["192.168.88.0/24"] * 2 and rules[0]["src-address-list"] == "!suro-admitted"
    assert SERVER in {r["address"] for r in addresses(tables)}  # Suro itself stays reachable and can route
    assert done.json()["subnet"]["state"] == "INSTALLED"
    # Leaving ALL while the subnet rule is in place would strand computers Suro does not know.
    assert set_mode(admin, "PILOT").json()["error"]["code"] == "admission.remove_subnet_gates_first"
    # The unknown computer installs the client from the page and asks to enroll; it still waits for approval.
    unseen = client.post("/api/v1/agent/onboarding-request", json={"csr": csr(), "macs": ["AA:00:00:00:00:99"], "hostname": "GHOST"})
    assert unseen.json()["token"] is None
    newcomer = client.post("/api/v1/agent/onboarding-request", json={"csr": csr(), "macs": [STRANGER], "hostname": "PC-NEW"}).json()
    assert newcomer["token"] and newcomer["primary_mac"] == STRANGER
    with app.state.sessions() as db:
        device = db.scalar(select(Device).where(Device.primary_mac == STRANGER))
        assert device.hostname == "PC-NEW" and not db.scalar(select(Enrollment).where(Enrollment.device_id == device.id)).approved
    # Removal deletes the drop rules first, then every entry this subnet created; manual entries stay.
    removal = admin.post(f"/api/v1/admission/subnets/{subnet['id']}/removal-preview", json={"reason": "end rollout"}).json()
    assert removal["plan"]["operations"][0]["path"] == "ip/firewall/filter"
    finished = admin.post(f"/api/v1/admission/subnets/{subnet['id']}/apply", json={"plan_id": removal["plan"]["id"], "reason": "end rollout"})
    assert finished.json()["state"] == "VERIFIED", finished.text
    assert [r["comment"] for r in tables["ip/firewall/filter"]] == ["defconf", "defconf"]
    assert [r["comment"] for r in tables["ip/firewall/address-list"]] == ["manual"]
    assert set_mode(admin, "PILOT").json()["mode"] == "PILOT"
    with app.state.sessions() as db:
        assert db.scalar(select(AdmissionSubnet)).state == "NOT_INSTALLED"
        assert all(not a.enabled for a in db.scalars(select(NetworkAdmission).where(NetworkAdmission.source == "ALL")))


def test_subnet_rules_have_one_narrow_shape():
    rule = {"method": "PUT", "path": "ip/firewall/filter",
            "data": {"chain": "forward", "src-address": "192.168.88.0/24", "src-address-list": "!suro-admitted",
                     "dst-address": "!" + SERVER, "action": "drop", "comment": "lantern:subnet:s1:admission:forward"}}
    firewall_shape(rule)
    for change in ({"src-address": "10.0.0.0/8"}, {"src-address": "192.168.88.1/24"}, {"src-address-list": None},
                   {"action": "accept"}, {"src-address": "fe80::/64"}, {"src-mac-address": MAC}):
        with pytest.raises(ValueError):
            firewall_shape({**rule, "data": {**rule["data"], **change}})
    with pytest.raises(ValueError):
        firewall_shape({**rule, "path": "ipv6/firewall/filter"})


def test_package_rules_accept_an_unsigned_setup_only(app):
    from app.api.deployments import Descriptor
    base = dict(name="Suro", sha256="a" * 64, size=10, kind="agent_update", expected_version="0.4.0")
    setup = Descriptor(**base, filename="SuroSetup.exe", architecture="any")
    assert setup.publisher_thumbprint == "" and setup.minimum_build == 14393
    for bad in (dict(filename="Suro.msi", product_code="{" + "0" * 8 + "-0000-0000-0000-" + "0" * 12 + "}"),
                dict(filename="Suro.msi", publisher_thumbprint="AB" * 20, architecture="any"),
                dict(filename="tool.exe", kind="exe")):
        with pytest.raises(ValueError):
            Descriptor(**{**base, **bad})


def test_onboarding_download_carries_this_servers_settings(client, app):
    content = b"MZ" + b"\0" * 4000
    sha = hashlib.sha256(content).hexdigest()
    objects = app.state.settings.data_dir / "repository" / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    (objects / sha).write_bytes(content)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "testserver")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    (app.state.settings.data_dir / "tls").mkdir(exist_ok=True)
    (app.state.settings.data_dir / "tls" / "server.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    with app.state.sessions.begin() as db:
        db.add(SoftwarePackage(name="Suro", filename="SuroSetup.exe", sha256=sha, size=len(content), kind="agent_update",
                               publisher_thumbprint="", approved_by=db.scalar(select(Administrator.id)),
                               metadata_={"expected_version": "0.4.0", "architecture": "any"}))
    page = client.get("/onboard?lang=ru")
    assert 'href="/onboard/installer?lang=ru"' in page.text and 'download="SuroSetup.exe"' in page.text
    download = client.get("/onboard/installer?lang=ru")
    assert download.status_code == 200 and "SuroSetup.exe" in download.headers["content-disposition"]
    body = download.content
    assert body.startswith(content) and body.endswith(b"SUROCFG1")
    length = struct.unpack("<I", body[-12:-8])[0]
    site = json.loads(body[-12 - length:-12])
    assert set(site) == {"server", "signing_public_key", "agent_publisher_thumbprint", "server_certificate_sha256", "ui_language"}
    assert site["server"] == "https://testserver" and "BEGIN PUBLIC KEY" in site["signing_public_key"] and site["ui_language"] == "ru"
    assert site["server_certificate_sha256"] == hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert int(download.headers["content-length"]) == len(body)
    # The settings never contain a token or private key.
    assert "PRIVATE" not in body[-12 - length:].decode()
    app.state.settings.public_origin = "https://localhost"
    assert client.get("/onboard/installer").json()["error"]["code"] == "onboarding.public_origin_not_reachable"
