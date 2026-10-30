import asyncio
import base64
import hashlib
import json
import secrets
import re
from datetime import timedelta
from urllib.parse import urlparse
import asyncssh
from app.services.safety import ensure_router_write
from sqlalchemy import select, update, or_, and_, exists
from app.db import utcnow
from app.models import (
    Router,
    NetworkBatch,
    OperationTarget,
    ConfigurationBackup,
    SoftwarePackage,
    BackgroundJob,
)
from app.mikrotik.connector import STACKS, redact
from app.security.crypto import canonical, digest
from app.services.network import connector
from app.services.telemetry import uptime_seconds
from app.auth.dependencies import audit

DISRUPTIVE = {
    "reboot",
    "wireless",
    "restore_fields",
    "binary_restore",
    "upgrade",
    "template",
}


def config_operations(router, parameters, snapshot):
    stack = parameters.get("stack")
    if stack not in router.capabilities.get("stacks", []):
        raise ValueError("network.stack_unsupported")
    path = STACKS[stack][0]
    name = parameters.get("interface")
    row = next((r for r in snapshot.get(path, []) if r.get("name") == name), None)
    if not row:
        raise ValueError("network.interface_not_found")
    fields = {}
    if "disabled" in parameters:
        if not isinstance(parameters["disabled"], bool):
            raise ValueError("network.invalid_disabled")
        fields["disabled"] = "true" if parameters["disabled"] else "false"
    if "ssid" in parameters:
        value = parameters["ssid"]
        if (
            not isinstance(value, str)
            or not 1 <= len(value.encode()) <= 32
            or any(ord(c) < 32 for c in value)
        ):
            raise ValueError("network.invalid_ssid")
        fields["configuration.ssid" if stack == "wifi" else "ssid"] = value
    for key, target in {
        "frequency": "channel.frequency" if stack == "wifi" else "frequency",
        "channel_width": "channel.width" if stack == "wifi" else "channel-width",
    }.items():
        if key in parameters:
            if target not in row:
                raise ValueError("network.field_capability_unverified")
            value = str(parameters[key])
            if key == "frequency" and (
                not value.isdigit() or not 2300 <= int(value) <= 7125
            ):
                raise ValueError("network.invalid_frequency")
            if key == "channel_width" and value not in {
                "20mhz",
                "20/40mhz",
                "20/40/80mhz",
                "20/40/80/160mhz",
                "20/40mhz-Ce",
                "20/40mhz-eC",
                "20/40/80mhz-Ceee",
            }:
                raise ValueError("network.invalid_channel_width")
            fields[target] = value
    if not fields:
        raise ValueError("network.no_changes")
    return [
        {
            "path": path,
            "id": row[".id"],
            "name": name,
            "before": {k: row.get(k) for k in fields},
            "after": fields,
        }
    ]


def preview_router(app, db, router, operation, parameters):
    snapshot = (
        json.loads(app.state.vault.open(router.snapshot)) if router.snapshot else {}
    )
    if (
        not snapshot
        or not router.last_inventory
        or (utcnow() - router.last_inventory).total_seconds() > 1800
    ):
        raise ValueError("router.fresh_discovery_required")
    changes = []
    if operation in ("wireless", "template"):
        changes = config_operations(router, parameters, snapshot)
    elif operation == "identity":
        value = parameters.get("name", "")
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 64
            or any(ord(c) < 32 for c in value)
        ):
            raise ValueError("network.invalid_name")
        row = next(iter(snapshot.get("system/identity", [])), {})
        changes = [
            {
                "path": "system/identity",
                "id": row.get(".id", "*0"),
                "before": {"name": row.get("name")},
                "after": {"name": value},
            }
        ]
    elif operation == "restore_fields":
        backup = db.get(ConfigurationBackup, parameters.get("backup_id"))
        if not backup or backup.router_id != router.id:
            raise ValueError("network.backup_not_found")
        for change in backup.metadata_.get("changes", []):
            if any(v is None for v in change["before"].values()):
                raise ValueError("network.unset_field_requires_manual_restore")
            changes.append(
                {**change, "before": change["after"], "after": change["before"]}
            )
        if not changes:
            raise ValueError("network.no_reversible_fields")
    elif operation in ("binary_backup", "binary_restore", "upgrade"):
        if not router.ssh_host_key:
            raise ValueError("network.pinned_sftp_required")
        if operation == "binary_restore":
            backup = db.get(ConfigurationBackup, parameters.get("backup_id"))
            if not backup or backup.router_id != router.id or backup.kind != "BINARY":
                raise ValueError("network.backup_not_found")
            if (
                not router.inventory.get("serial_number")
                or backup.metadata_.get("version") != router.inventory.get("version")
                or backup.metadata_.get("serial")
                != router.inventory.get("serial_number")
            ):
                raise ValueError("network.backup_device_version_mismatch")
        if operation == "upgrade":
            package = db.get(SoftwarePackage, parameters.get("package_id"))
            if not package or package.kind != "routeros" or not package.approved_by:
                raise ValueError("package.approval_required")
            if package.metadata_.get("architecture") != router.inventory.get(
                "architecture"
            ):
                raise ValueError("network.package_architecture_mismatch")
            installed = re.match(
                r"^([67])\.(\d+)(?:\.(\d+))?", router.inventory.get("version", "")
            )
            desired = re.match(
                r"^([67])\.(\d+)(?:\.(\d+))?",
                package.metadata_.get("release_version", ""),
            )
            if (
                not installed
                or not desired
                or installed[1] != desired[1]
                or tuple(int(n or 0) for n in desired.groups())
                <= tuple(int(n or 0) for n in installed.groups())
            ):
                raise ValueError("network.upgrade_transition_requires_manual_review")
            changes = [
                {
                    "package_id": package.id,
                    "sha256": package.sha256,
                    "expected_version": package.metadata_.get("release_version"),
                }
            ]
    elif operation not in ("reboot", "snapshot", "diagnostics"):
        raise ValueError("network.operation_not_allowed")
    baseline = {
        p: snapshot.get(p, []) for p in {c["path"] for c in changes if "path" in c}
    }
    return {
        "generation": router.generation,
        "baseline": baseline,
        "baseline_hash": digest(canonical(baseline)),
        "changes": changes,
        "compatible": True,
        "impact": "network.wifi_interruption"
        if operation in DISRUPTIVE
        else "network.read_only",
        "model": router.inventory.get("model"),
        "version": router.inventory.get("version"),
    }


async def sftp(app, router, callback):
    # Only backup/restore/upgrade use SFTP and each writes a file on the router.
    ensure_router_write(app.state.settings, router)
    host = urlparse(router.base_url).hostname
    async with asyncssh.connect(
        host,
        username=router.username,
        password=app.state.vault.open(router.secret),
        known_hosts=([asyncssh.import_public_key(router.ssh_host_key)], [], []),
        login_timeout=10,
    ) as connection:
        async with connection.start_sftp_client() as client:
            return await asyncio.wait_for(callback(client), timeout=240)


async def binary_backup(app, db, router, api, actor):
    name = "suro-" + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    await api.command(
        "system/backup/save",
        {"name": name, "password": password, "encryption": "aes-sha256"},
    )

    async def download(client):
        async with client.open(name + ".backup", "rb") as source:
            value = await source.read(8 * 1024**2 + 1)
            if len(value) > 8 * 1024**2:
                raise ValueError("network.backup_size_limit")
            return value

    data = await sftp(app, router, download)
    backup = ConfigurationBackup(
        router_id=router.id,
        author_id=actor,
        kind="BINARY",
        content_hash=digest(data),
        encrypted_content=app.state.vault.seal(
            json.dumps({"data": base64.b64encode(data).decode(), "password": password})
        ),
        metadata_={
            "serial": router.inventory.get("serial_number"),
            "version": router.inventory.get("version"),
            "router_file": name + ".backup",
        },
    )
    db.add(backup)
    db.flush()
    return backup


async def execute_target(app, db, batch, target):
    r = db.get(Router, target.router_id)
    if batch.automatic:
        if (
            not app.state.settings.recovery_enabled
            or not r.recovery_policy.get("enabled")
            or r.role != "ACCESS_POINT"
            or r.protected
        ):
            raise ValueError("recovery.disabled")
        from app.services.recovery import recovery_environment

        allowed, allow_reboot = recovery_environment(
            db.scalars(select(Router).where(Router.archived.is_(False))).all(), utcnow()
        )
        if not allowed or batch.operation == "reboot" and not allow_reboot:
            raise ValueError("recovery.upstream_or_shared_failure")
        conditions = r.recovery_policy.get("conditions", ["resource_pressure"])
        if (
            batch.operation == "reboot"
            and "resource_pressure" not in conditions
            or batch.operation == "wireless"
            and "unexpected_radio_disabled" not in conditions
        ):
            raise ValueError("recovery.disabled")
        if r.recovery_policy.get("require_maintenance_window", True):
            from app.models import MaintenanceWindow

            windows = db.scalars(
                select(MaintenanceWindow).where(
                    MaintenanceWindow.starts_at <= utcnow(),
                    MaintenanceWindow.ends_at >= utcnow(),
                )
            ).all()
            if not any(r.id in window.router_ids for window in windows):
                raise ValueError("recovery.maintenance_window_required")
    if (
        batch.operation in DISRUPTIVE
        and (r.protected or r.role == "GATEWAY")
        and (
            r.name not in batch.parameters.get("confirmed_protected", [])
            or not batch.parameters.get("out_of_band_confirmed")
        )
    ):
        raise ValueError("network.protected_confirmation_required")
    if r.archived:
        raise ValueError("network.writes_disabled")
    if batch.operation not in ("snapshot", "diagnostics"):
        ensure_router_write(app.state.settings, r)
    if r.generation != target.preview["generation"]:
        raise ValueError("network.concurrent_change")
    claim = db.execute(
        update(Router)
        .where(
            Router.id == r.id,
            (Router.lock_until.is_(None) | (Router.lock_until < utcnow())),
        )
        .values(lock_until=utcnow() + timedelta(minutes=10))
    ).rowcount
    if claim != 1:
        raise ValueError("network.concurrent_change")
    target.state, target.started_at, target.deadline = (
        "RUNNING",
        utcnow(),
        utcnow() + timedelta(minutes=10),
    )
    db.commit()
    try:
        async with connector(app, r) as api:
            resource = (await api.read("system/resource"))[
                0
            ]  # Must actually reach API before issuing any reboot.
            before_uptime = uptime_seconds(resource.get("uptime"))
            baseline = {p: await api.read(p) for p in target.preview["baseline"]}
            if digest(canonical(baseline)) != target.preview["baseline_hash"]:
                raise ValueError("network.configuration_changed")
            backup = ConfigurationBackup(
                router_id=r.id,
                author_id=batch.author_id,
                kind="SNAPSHOT",
                content_hash=digest(r.snapshot or ""),
                encrypted_content=r.snapshot,
                metadata_={
                    "changes": target.preview["changes"],
                    "version": r.inventory.get("version"),
                },
            )
            db.add(backup)
            db.flush()
            target.result = {
                "backup_id": backup.id,
                "before_uptime": before_uptime,
                "issued_at": utcnow().isoformat(),
            }
            db.commit()
            op = batch.operation
            if op in ("wireless", "identity", "template", "restore_fields"):
                for change in target.preview["changes"]:
                    await api.configure(change["path"], change["id"], change["after"])
                    rows = await api.read(change["path"])
                    actual = (
                        next(iter(rows), {})
                        if change["path"] == "system/identity"
                        else next(
                            (row for row in rows if row.get(".id") == change["id"]), {}
                        )
                    )
                    if any(actual.get(k) != v for k, v in change["after"].items()):
                        raise ValueError("network.readback_failed")
                r.generation += 1
                target.state = "SUCCEEDED"
                if op in ("wireless", "template"):
                    r.desired_config = {
                        **r.desired_config,
                        batch.parameters.get("interface", ""): batch.parameters,
                    }
            elif op == "snapshot":
                target.state = "SUCCEEDED"
            elif op == "binary_backup":
                saved = await binary_backup(app, db, r, api, batch.author_id)
                target.result = {**target.result, "binary_backup_id": saved.id}
                target.state = "SUCCEEDED"
            elif op == "diagnostics":
                address = batch.parameters.get("address", urlparse(r.base_url).hostname)
                import ipaddress

                ip = ipaddress.ip_address(address)
                if not any(
                    ip in ipaddress.ip_network(n.strip())
                    for n in app.state.settings.router_allowed_networks.split(",")
                ):
                    raise ValueError("network.diagnostic_address_not_allowed")
                result = await api.command(
                    "ping", {"address": str(ip), "count": "3", "interval": "200ms"}
                )
                target.result = {**target.result, "observations": redact(result)}
                target.state = "SUCCEEDED"
            else:
                if op == "upgrade":
                    await binary_backup(app, db, r, api, batch.author_id)
                    package = db.get(SoftwarePackage, batch.parameters["package_id"])
                    path = (
                        app.state.settings.data_dir
                        / "repository/objects"
                        / package.sha256
                    )

                    def package_hash():
                        with path.open("rb") as source:
                            return hashlib.file_digest(source, "sha256").hexdigest()

                    if await asyncio.to_thread(package_hash) != package.sha256:
                        raise ValueError("package.hash_mismatch")

                    async def upload(client):
                        await client.put(
                            str(path), "suro-approved-" + package.id + ".npk"
                        )

                    await sftp(app, r, upload)
                    target.result = {
                        **target.result,
                        "expected_version": package.metadata_["release_version"],
                    }
                elif op == "binary_restore":
                    saved = db.get(ConfigurationBackup, batch.parameters["backup_id"])
                    content = json.loads(app.state.vault.open(saved.encrypted_content))
                    name = "suro-restore-" + saved.id + ".backup"

                    async def upload(client):
                        async with client.open(name, "wb") as output:
                            await output.write(base64.b64decode(content["data"]))

                    await sftp(app, r, upload)
                # Persist uncertainty BEFORE a potentially disconnecting command. Never replay it after a crash.
                target.state = "WAITING_RECONNECT"
                db.commit()
                try:
                    await api.command(
                        "system/backup/load",
                        {"name": name, "password": content["password"]},
                    ) if op == "binary_restore" else await api.command("system/reboot")
                except Exception:
                    target.result = {
                        **target.result,
                        "command_acknowledgment": "UNKNOWN",
                    }
                db.commit()
            audit(
                db,
                batch.author_id or "automatic-recovery",
                "network.operation_issued",
                r.id,
                batch_id=batch.id,
                target_id=target.id,
                operation=op,
            )
    finally:
        r.lock_until = None
        db.commit()


async def verify_reboot(app, db, batch, target):
    r = db.get(Router, target.router_id)
    try:
        async with connector(app, r) as api:
            resource = (await api.read("system/resource"))[0]
        uptime = uptime_seconds(resource.get("uptime"))
        elapsed = (utcnow() - target.started_at).total_seconds()
        before = target.result.get("before_uptime")
        # A responding API alone is not evidence that the device rebooted.
        rebooted = (
            uptime is not None
            and before is not None
            and uptime < before + elapsed - 5
            and uptime <= elapsed + 30
        )
        version_ok = (
            not target.result.get("expected_version")
            or resource.get("version", "").split(" ")[0]
            == target.result["expected_version"]
        )
        if rebooted and version_ok:
            target.state = "SUCCEEDED"
            target.result = {
                **target.result,
                "verified_uptime": uptime,
                "version": resource.get("version"),
            }
            r.last_reboot = utcnow() - timedelta(seconds=uptime)
            r.generation += 1
    except Exception:
        pass
    if target.state != "SUCCEEDED" and target.deadline < utcnow():
        target.state = "FAILED"
        target.result = {**target.result, "code": "network.reboot_unverified"}


async def process_batches(app):
    with app.state.sessions() as db:
        lease_id = "00000000-0000-0000-0000-000000007281"
        owner = secrets.token_hex(12)
        if not db.get(BackgroundJob, lease_id):
            # The single configured worker creates this record; concurrent initializers retry next tick.
            try:
                db.add(
                    BackgroundJob(
                        id=lease_id, kind="INFRA_LEASE", available_at=utcnow()
                    )
                )
                db.commit()
            except Exception:
                db.rollback()
                return
        acquired = db.execute(
            update(BackgroundJob)
            .where(BackgroundJob.id == lease_id, BackgroundJob.available_at <= utcnow())
            .values(status=owner, available_at=utcnow() + timedelta(minutes=10))
        ).rowcount
        db.commit()
        if acquired != 1:
            return
        try:
            active_target = exists(
                select(OperationTarget.id).where(
                    OperationTarget.batch_id == NetworkBatch.id,
                    OperationTarget.state.in_(["WAITING_RECONNECT", "RUNNING"]),
                )
            )
            batches = db.scalars(
                select(NetworkBatch)
                .where(
                    NetworkBatch.kind == "NETWORK",
                    or_(
                        NetworkBatch.state.in_(["APPROVED", "RUNNING"]),
                        and_(NetworkBatch.state == "CANCELLED", active_target),
                    ),
                    NetworkBatch.not_before <= utcnow(),
                )
                .order_by(NetworkBatch.not_before)
                .limit(20)
            ).all()
            for batch in batches:
                targets = db.scalars(
                    select(OperationTarget)
                    .where(OperationTarget.batch_id == batch.id)
                    .order_by(OperationTarget.created_at, OperationTarget.id)
                ).all()
                for target in targets:
                    if target.state == "WAITING_RECONNECT":
                        await verify_reboot(app, db, batch, target)
                    elif (
                        target.state == "RUNNING"
                        and target.deadline
                        and target.deadline < utcnow()
                    ):
                        target.state = "UNKNOWN"
                if batch.state == "CANCELLED":
                    db.commit()
                    continue
                if (
                    any(t.state in ("FAILED", "UNKNOWN") for t in targets)
                    and batch.stop_on_failure
                ):
                    batch.state = "STOPPED"
                    db.commit()
                    continue
                if any(t.state in ("WAITING_RECONNECT", "RUNNING") for t in targets):
                    db.commit()
                    break
                pending = [t for t in targets if t.state == "PENDING"]
                if not pending:
                    batch.state = "COMPLETED"
                    db.commit()
                    continue
                if batch.window_end and batch.window_end < utcnow():
                    batch.state = "WINDOW_EXPIRED"
                    db.commit()
                    continue
                for target in pending[: batch.batch_size]:
                    r = db.get(Router, target.router_id)
                    if batch.operation in DISRUPTIVE:
                        # An arbitrary responding router is not proof of an independent management path.
                        independent = batch.parameters.get(
                            "independent_management_router_ids", []
                        )
                        if batch.automatic:
                            independent = [
                                i
                                for i in independent
                                if i
                                in r.recovery_policy.get(
                                    "independent_management_router_ids", []
                                )
                            ]
                        if not isinstance(independent, list) or len(independent) > 16:
                            independent = []
                        others = db.scalars(
                            select(Router).where(
                                Router.archived.is_(False),
                                Router.id != r.id,
                                Router.status == "ONLINE",
                                Router.id.in_(independent),
                            )
                        ).all()
                        restarting = set(
                            db.scalars(
                                select(OperationTarget.router_id).where(
                                    OperationTarget.state.in_(
                                        ["WAITING_RECONNECT", "RUNNING"]
                                    ),
                                    OperationTarget.router_id.is_not(None),
                                )
                            )
                        )
                        if not batch.parameters.get(
                            "out_of_band_confirmed"
                        ) and not any(
                            o.id not in restarting
                            and o.last_seen
                            and (utcnow() - o.last_seen).total_seconds() < 180
                            for o in others
                        ):
                            target.state = "FAILED"
                            target.result = {"code": "network.last_management_path"}
                            break
                    try:
                        await asyncio.wait_for(
                            execute_target(app, db, batch, target), timeout=480
                        )
                    except Exception as exc:
                        if target.state != "WAITING_RECONNECT":
                            target.state = (
                                "UNKNOWN" if isinstance(exc, TimeoutError) else "FAILED"
                            )
                        target.result = {
                            **target.result,
                            "code": str(exc)
                            if isinstance(exc, ValueError)
                            else "network.operation_failed",
                        }
                    if (
                        target.state in ("FAILED", "WAITING_RECONNECT")
                        and batch.stop_on_failure
                    ):
                        break
                batch.state = "RUNNING"
                db.commit()
                break  # One active infrastructure batch at a time, independent of software transfers.
        finally:
            db.execute(
                update(BackgroundJob)
                .where(BackgroundJob.id == lease_id, BackgroundJob.status == owner)
                .values(available_at=utcnow())
            )
            db.commit()
