"""Persisted portal settings (override env defaults where stored)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.app.config import settings
from api.app.models import PortalSetting

AQUA_PACKAGES_TTL_KEY = "aqua_packages_ttl_hours"


def get_aqua_packages_ttl_hours(db: Session | None = None) -> int:
    """TTL for Aqua package catalog cache; DB value wins over env when set."""
    default = max(1, int(settings.aqua_packages_ttl_hours or 168))

    def _read(session: Session) -> int:
        row = session.get(PortalSetting, AQUA_PACKAGES_TTL_KEY)
        if not row or not (row.value or "").strip():
            return default
        try:
            return max(1, min(8760, int(row.value.strip())))
        except ValueError:
            return default

    if db is not None:
        return _read(db)
    from api.app.db import db_session

    with db_session() as session:
        return _read(session)


def set_aqua_packages_ttl_hours(db: Session, hours: int) -> int:
    value = max(1, min(8760, int(hours)))
    row = db.get(PortalSetting, AQUA_PACKAGES_TTL_KEY)
    if row:
        row.value = str(value)
    else:
        db.add(PortalSetting(key=AQUA_PACKAGES_TTL_KEY, value=str(value)))
    db.commit()
    return value
