import base64
import json
from datetime import timedelta
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from app.db import utcnow
from app.models import Device, DeploymentTask, Upload, AuditLog
from app.services.transfers import TransferBudget
from app.services.repository import clean_uploads
from test_agent_protocol import enrolled, signed_request
from test_deployments import upload_package


def prepare_task(admin, app, enrolled):
    d, key, fp, _ = enrolled
    package = upload_package(admin).json()["package_id"]
    admin.post(
        f"/api/v1/packages/{package}/approve",
        json={"reason": "Isolated completion contract"},
    )
    app.state.settings.deployment_enabled = True
    with app.state.sessions.begin() as db:
        db.get(Device, d["id"]).mode = "APPROVED_REMEDIATION"
    job = admin.post(
        "/api/v1/deployments",
        json={
            "package_id": package,
            "device_ids": [d["id"]],
            "reason": "Controlled test deployment",
        },
    ).json()
    claimed = signed_request(
        admin, key, fp, "GET", "/api/v1/agent/deployments/next"
    ).json()["task"]
    manifest = json.loads(base64.b64decode(claimed["payload"]))
    return d, key, fp, manifest, package


def test_reboot_completion_requires_explicit_fresh_readback(admin, app, enrolled):
    d, key, fp, m, _ = prepare_task(admin, app, enrolled)
    path = f"/api/v1/agent/deployments/{m['task_id']}/result"
    assert (
        signed_request(
            admin,
            key,
            fp,
            "POST",
            path,
            {
                "attempt": 1,
                "state": "REBOOT_REQUIRED",
                "details": {"boot_time": "2026-10-29T00:00:00Z"},
            },
        ).status_code
        == 200
    )
    tickets = signed_request(
        admin, key, fp, "GET", "/api/v1/agent/deployments/pending-verification"
    ).json()["tasks"]
    ticket = json.loads(base64.b64decode(tickets[0]["payload"]))
    assert (
        ticket["purpose"] == "verify_deployment"
        and ticket["device_id"] == d["id"]
        and ticket["expires_at"].endswith("Z")
    )
    assert ticket["previous_boot_time"] == "2026-10-29T00:00:00Z"
    assert (
        signed_request(
            admin,
            key,
            fp,
            "POST",
            path,
            {"attempt": 1, "state": "SUCCEEDED", "verified": True},
        ).status_code
        == 422
    )
    assert (
        signed_request(
            admin,
            key,
            fp,
            "POST",
            path,
            {
                "attempt": 1,
                "state": "SUCCEEDED",
                "verified": True,
                "details": {"reboot_observed": True, "source": "windows_readback"},
            },
        ).status_code
        == 200
    )


def test_stale_attempt_result_cannot_overwrite_a_retry(admin, app, enrolled):
    _, key, fp, m, _ = prepare_task(admin, app, enrolled)
    with app.state.sessions.begin() as db:
        task = db.get(DeploymentTask, m["task_id"])
        task.attempt = 2
        task.state = "RUNNING"
    response = signed_request(
        admin,
        key,
        fp,
        "POST",
        f"/api/v1/agent/deployments/{m['task_id']}/result",
        {"attempt": 1, "state": "FAILED"},
    )
    assert response.status_code == 200 and response.json()["superseded"]
    with app.state.sessions() as db:
        assert db.get(DeploymentTask, m["task_id"]).state == "RUNNING"


def test_verification_download_does_not_hold_database_connection(
    admin, app, enrolled, monkeypatch
):
    _, key, fp, m, package = prepare_task(admin, app, enrolled)
    observed = []

    async def throttle(*args):
        observed.append(app.state.engine.pool.checkedout())

    monkeypatch.setattr(app.state.transfers, "throttle", throttle)
    response = signed_request(
        admin, key, fp, "GET", "/api/v1/agent/packages/" + package
    )
    assert response.status_code == 200 and observed == [0]
    assert app.state.transfers.active == {}


async def test_shared_transfer_concurrency_and_byte_budget(monkeypatch):
    from app.services import transfers

    b = TransferBudget()
    a = await b.reserve("first", 2)
    with pytest.raises(HTTPException):
        await b.reserve("first", 2)
    c = await b.reserve("second", 2)
    with pytest.raises(HTTPException):
        await b.reserve("third", 2)
    await b.release(a)
    await b.release(a)
    d = await b.reserve("third", 2)
    delays = []

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(transfers.asyncio, "sleep", sleep)
    monkeypatch.setattr(transfers.time, "monotonic", lambda: 100.0)
    await b.throttle(65536, 65536)
    await b.throttle(65536, 65536)
    assert delays == [1.0, 2.0]
    await b.release(c)
    await b.release(d)


def test_upload_retention_preserves_objects_and_security_audit(admin, app):
    upload = admin.post(
        "/api/v1/packages/uploads",
        json={
            "name": "Stale upload",
            "filename": "app.exe",
            "sha256": "b" * 64,
            "size": 10,
            "kind": "exe",
            "publisher_thumbprint": "A" * 40,
        },
    ).json()["upload_id"]
    root = app.state.settings.data_dir / "repository"
    obj = root / "objects" / "keep"
    obj.parent.mkdir(exist_ok=True)
    obj.write_bytes(b"must survive")
    with app.state.sessions.begin() as db:
        db.get(Upload, upload).created_at = utcnow() - timedelta(days=20)
        count = len(db.scalars(select(AuditLog)).all())
        clean_uploads(db, app.state.settings)
        assert (
            db.get(Upload, upload).descriptor["expired"]
            and len(db.scalars(select(AuditLog)).all()) >= count
        )
    assert (
        not (root / "uploads" / upload).exists() and obj.read_bytes() == b"must survive"
    )


def test_locale_completion_is_not_success_until_verified_and_new_request_supersedes(
    admin, app, enrolled
):
    d, key, fp, _ = enrolled
    with app.state.sessions.begin() as db:
        db.get(Device, d["id"]).mode = "MAINTENANCE"
    path = f"/api/v1/devices/{d['id']}/maintenance"
    body = {
        "operation": "windows.locale",
        "language": "hy-AM",
        "keyboard_layouts": ["042b:0000042b"],
        "reason": "Offline Armenian resources approved",
    }
    first = admin.post(path, json=body).json()["id"]
    signed_request(admin, key, fp, "GET", "/api/v1/agent/maintenance/next")
    result = f"/api/v1/agent/maintenance/{first}/result"
    assert (
        signed_request(
            admin,
            key,
            fp,
            "POST",
            result,
            {"state": "PENDING_USER_LOGON", "details": {"user_sid": "S-1-5-21-1001"}},
        ).status_code
        == 200
    )
    assert (
        signed_request(
            admin, key, fp, "POST", result, {"state": "SUCCEEDED", "details": {}}
        ).status_code
        == 422
    )
    second = admin.post(path, json=body).json()["id"]
    assert signed_request(
        admin, key, fp, "POST", result, {"state": "PENDING_USER_LOGON", "details": {}}
    ).json()["superseded"]
    assert (
        next(j for j in admin.get(path).json() if j["id"] == first)["status"]
        == "SUPERSEDED"
    )
    assert second != first


def test_custom_detector_and_agent_update_requirements_are_typed(admin):
    base = {
        "name": "Update",
        "filename": "agent.msi",
        "sha256": "a" * 64,
        "size": 10,
        "kind": "agent_update",
        "publisher_thumbprint": "A" * 40,
        "product_code": "{12345678-1234-1234-1234-123456789ABC}",
    }
    assert admin.post("/api/v1/packages/uploads", json=base).status_code == 422
    base["expected_version"] = "0.2.0"
    assert admin.post("/api/v1/packages/uploads", json=base).status_code == 201
    base.update(
        {
            "kind": "exe",
            "filename": "app.exe",
            "detection": {"kind": "shell", "path": "whoami"},
        }
    )
    assert admin.post("/api/v1/packages/uploads", json=base).status_code == 422
    base["detection"] = {
        "kind": "file_sha256",
        "path": "C:\\Users\\someone\\personal.txt",
        "sha256": "a" * 64,
    }
    assert admin.post("/api/v1/packages/uploads", json=base).status_code == 422


def test_staged_agent_update_keeps_concurrency_slot_until_verified(
    admin, app, enrolled
):
    _, key, fp, m, _ = prepare_task(admin, app, enrolled)
    app.state.settings.deployment_concurrency = 1
    with app.state.sessions.begin() as db:
        t = db.get(DeploymentTask, m["task_id"])
        t.manifest = {**t.manifest, "kind": "agent_update"}
    response = signed_request(
        admin,
        key,
        fp,
        "POST",
        f"/api/v1/agent/deployments/{m['task_id']}/result",
        {"attempt": 1, "state": "AWAITING_RESTART"},
    )
    assert response.status_code == 200
    with app.state.sessions() as db:
        t = db.get(DeploymentTask, m["task_id"])
        assert t.lease_until and t.lease_until > utcnow()
    assert (
        signed_request(admin, key, fp, "GET", "/api/v1/agent/deployments/next").json()[
            "task"
        ]
        is None
    )
