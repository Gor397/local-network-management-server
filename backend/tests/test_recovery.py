import os
from datetime import timedelta
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select
from cryptography.fernet import Fernet
from app.db import utcnow
from app.models import Device, PolicyVersion, Alert, HealthReport, AuditLog
from app.workers.main import expire_evidence
from app.security.crypto import canonical, digest
from test_foundation import create_device, create_policy


def test_alembic_upgrade_downgrade_roundtrip(tmp_path,monkeypatch):
    backend=Path(__file__).resolve().parents[1]
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/migrations.db')
    monkeypatch.setenv('ENCRYPTION_KEY',Fernet.generate_key().decode())
    config=Config(str(backend/'alembic.ini'))
    config.set_main_option('script_location',str(backend/'migrations'))
    command.upgrade(config,'head')
    engine=create_engine(f'sqlite:///{tmp_path}/migrations.db')
    from app.db import Base
    assert len(inspect(engine).get_table_names())==len(Base.metadata.tables)+1
    assert any(c['column_names']==['address'] for c in inspect(engine).get_unique_constraints('dhcp_reservations'))
    command.downgrade(config,'base')
    assert inspect(engine).get_table_names()==['alembic_version']
    engine.dispose()


def test_worker_expires_heartbeat_and_preserves_security_audit(admin,app):
    d=create_device(admin)
    _,v=create_policy(admin)
    with app.state.sessions.begin() as db:
        device=db.get(Device,d['id']);device.policy_version_id=v['id'];device.state='COMPLIANT';device.compliance_score=100
        device.last_heartbeat=utcnow()-timedelta(hours=1);device.last_verified=utcnow()
        db.add(HealthReport(device_id=device.id,metrics={},created_at=utcnow()-timedelta(days=30)))
        audit=AuditLog(actor_id='test',action='security.audit',target_id=device.id,details={},created_at=utcnow()-timedelta(days=1000));db.add(audit)
        db.flush();audit_id=audit.id
        expire_evidence(db,app.state.settings)
    with app.state.sessions() as db:
        assert db.get(Device,d['id']).state=='UNVERIFIED'
        assert db.get(Device,d['id']).compliance_score==0
        assert db.scalar(select(Alert).where(Alert.code=='agent.heartbeat_missing'))
        assert db.scalar(select(HealthReport).where(HealthReport.device_id==d['id'])) is None
        assert db.get(AuditLog,audit_id)
