"""Conservative cleanup: security audit and content-addressed package objects are retained."""

from datetime import timedelta
from sqlalchemy import select
from app.db import utcnow
from app.models import Upload
from app.auth.dependencies import audit


def clean_uploads(db, settings, now=None):
    now = now or utcnow()
    root = settings.data_dir / "repository/uploads"
    for upload in db.scalars(
        select(Upload)
        .where(Upload.created_at < now - timedelta(days=settings.upload_retention_days))
        .with_for_update(skip_locked=True)
        .limit(100)
    ):
        if not upload.completed:
            upload.completed = True
            upload.descriptor = {**upload.descriptor, "expired": True}
            audit(db, "retention-worker", "package.upload_expired", upload.id)
        path = root / upload.id
        if path.is_file() and not path.is_symlink():
            path.unlink()
    # Removed/completed upload records do not authorize deleting a package object.
