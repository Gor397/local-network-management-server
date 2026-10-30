from pathlib import Path
from uuid import uuid4
from datetime import datetime
import json
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text


def test_upgrade_preserves_legacy_inventory_and_credentials(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/existing-installation.db"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    command.upgrade(config, "0003_policy_scopes")
    engine = create_engine(url)
    device_id, router_id = str(uuid4()), str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            text("""INSERT INTO devices (id,created_at,hostname,device_class,primary_mac,mode,state,compliance_score,network_state,inventory,network_evidence,enabled,revision)
            VALUES (:id,:at,'Existing PC','STANDARD','00:11:22:33:44:55','AUDIT','UNVERIFIED',0,'UNKNOWN',:inventory,'{}',1,7)"""),
            {
                "id": device_id,
                "at": datetime.utcnow(),
                "inventory": json.dumps({"important_existing_state": "preserve"}),
            },
        )
        connection.execute(
            text("""INSERT INTO routers (id,created_at,name,base_url,username,secret,capabilities,status,write_enabled,generation)
            VALUES (:id,:at,'Existing router','https://192.168.88.1','existing-account','ENCRYPTED-CREDENTIAL','{}','UNKNOWN',0,4)"""),
            {"id": router_id, "at": datetime.utcnow()},
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        device = (
            connection.execute(
                text("SELECT * FROM devices WHERE id=:id"), {"id": device_id}
            )
            .mappings()
            .one()
        )
        router = (
            connection.execute(
                text("SELECT * FROM routers WHERE id=:id"), {"id": router_id}
            )
            .mappings()
            .one()
        )
        assert (
            device["hostname"] == "Existing PC"
            and device["revision"] == 7
            and "preserve" in device["inventory"]
        )
        assert (
            device["identity_status"] == "PENDING"
            and not device["owner_verified"]
            and device["owner_name"] is None
        )
        assert (
            router["secret"] == "ENCRYPTED-CREDENTIAL"
            and router["generation"] == 4
            and router["role"] == "ROUTER"
        )
        assert (
            router["transport"] == "REST"
            and json.loads(router["recovery_policy"]) == {}
        )
    engine.dispose()
