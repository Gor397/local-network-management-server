import argparse
import getpass
import json
import os
import secrets
from pathlib import Path
from sqlalchemy import select
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from app.config import Settings
from app.db import database
from app.models import Administrator, Role, AdminSession, AuditLog
from app.auth.dependencies import PERMISSIONS
from app.security.crypto import initialize_keys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init", "create-admin", "recover-admin"])
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()
    if args.command == "init":
        root = Path(os.environ.get("DATA_DIR", "data"))
        initialize_keys(root / "keys")
        for folder in ("trust", "repository", "recordings"):
            (root / folder).mkdir(exist_ok=True, mode=0o700)
        env = Path(".env")
        if env.exists():
            print("Existing .env preserved. Key files initialized without replacement.")
            return
        database_password = secrets.token_urlsafe(32)
        env.write_text(f"POSTGRES_USER=lantern\nPOSTGRES_DB=lantern\nPOSTGRES_PASSWORD={database_password}\n"
                       f"DATABASE_URL=postgresql+psycopg://lantern:{database_password}@db/lantern\n"
                       f"ENCRYPTION_KEY={Fernet.generate_key().decode()}\nDATA_DIR=/data\n"
                       "PUBLIC_ORIGIN=https://localhost\nTRUSTED_HOSTS=localhost,127.0.0.1\nCOOKIE_SECURE=true\n"
                       "LOW_RESOURCE_MODE=true\nROUTER_WRITES_ENABLED=false\nDEPLOYMENT_ENABLED=false\nSSH_ENABLED=false\n")
        env.chmod(0o600)
        print("Generated .env and local identity keys. Set PUBLIC_ORIGIN and TRUSTED_HOSTS before deployment.")
        return
    settings = Settings()
    _, sessions = database(settings.database_url)
    password = getpass.getpass("New administrator password (at least 16 characters): ")
    if len(password) < 16 or password != getpass.getpass("Confirm password: "):
        raise SystemExit("Password must match and contain at least 16 characters.")
    with sessions.begin() as db:
        for role, permissions in PERMISSIONS.items():
            if not db.get(Role, role):
                db.add(Role(name=role, permissions=sorted(permissions)))
        db.flush()
        admin = db.scalar(select(Administrator).where(Administrator.username == args.username))
        if args.command == "create-admin":
            if admin:
                raise SystemExit("Administrator already exists; use documented recovery.")
            admin = Administrator(username=args.username, password_hash=PasswordHasher().hash(password), role="owner")
            db.add(admin)
            db.flush()
            action = "admin.created_locally"
        else:
            if not admin:
                raise SystemExit("Administrator not found.")
            admin.password_hash, admin.totp_secret, admin.enabled = PasswordHasher().hash(password), None, True
            for session in db.scalars(select(AdminSession).where(AdminSession.admin_id == admin.id)):
                db.delete(session)
            action = "admin.recovered_locally"
        db.add(AuditLog(actor_id="local-console", action=action, target_id=admin.id, details={}))
    print("Administrator saved. Username/password login is available; optional TOTP is in Settings.")


if __name__ == "__main__":
    main()
