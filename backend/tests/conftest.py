from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from app.config import Settings
from app.db import Base, utcnow
from app.models import Role, Administrator, AdminSession
from app.security.crypto import initialize_keys
from app.main import create_app
from app.auth.dependencies import PERMISSIONS


@pytest.fixture(scope="session")
def identity_keys(tmp_path_factory):
    directory = tmp_path_factory.mktemp("identity")
    initialize_keys(directory / "keys")
    return directory


@pytest.fixture
def app(tmp_path, identity_keys):
    import shutil
    shutil.copytree(identity_keys / "keys", tmp_path / "keys")
    settings = Settings(database_url=f"sqlite:///{tmp_path}/test.db", data_dir=tmp_path,
                        public_origin="https://testserver", trusted_hosts="testserver", encryption_key=Fernet.generate_key().decode())
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    with app.state.sessions.begin() as db:
        for role, permissions in PERMISSIONS.items():
            db.add(Role(name=role, permissions=list(permissions)))
        db.flush()
        db.add(Administrator(username="owner", password_hash=PasswordHasher().hash("test-password-at-least-16"), role="owner"))
        db.add(Administrator(username="viewer", password_hash=PasswordHasher().hash("test-password-at-least-16"), role="viewer"))
    yield app
    app.state.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app, base_url="https://testserver") as client:
        yield client


@pytest.fixture
def admin(client, app):
    result = client.post("/api/v1/auth/login", headers={"origin": "https://testserver"},
                         json={"username": "owner", "password": "test-password-at-least-16"})
    assert result.status_code == 200, result.text
    client.headers.update({"origin": "https://testserver", "x-csrf-token": result.json()["csrf"]})
    with app.state.sessions.begin() as db:
        for session in db.query(AdminSession):
            session.mfa_at = utcnow()
    return client
