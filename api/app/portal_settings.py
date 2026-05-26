"""Persisted portal settings (override env defaults where stored)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.app.config import settings
from api.app.models import PortalSetting

AQUA_PACKAGES_TTL_KEY       = "aqua_packages_ttl_hours"
AQUA_RECHECK_ON_SYNC_KEY    = "aqua_recheck_on_sync"  # legacy
REWRITE_PLAT_PACKAGE_NAME_ON_SYNC_KEY = "rewrite_plat_package_name_on_sync"
AQUA_PREFERRED_REGISTRY_KEY = "aqua_preferred_registry"
AQUA_DEFAULT_IMAGE_TAG_KEY  = "aqua_default_image_tag"


def _get_str(db: Session | None, key: str, default: str) -> str:
    def _read(session: Session) -> str:
        row = session.get(PortalSetting, key)
        if not row or not (row.value or "").strip():
            return default
        return row.value.strip()

    if db is not None:
        return _read(db)
    from api.app.db import db_session
    with db_session() as session:
        return _read(session)


def _set_str(db: Session, key: str, value: str) -> str:
    row = db.get(PortalSetting, key)
    if row:
        row.value = value
    else:
        db.add(PortalSetting(key=key, value=value))
    db.commit()
    return value


# ─── TTL ──────────────────────────────────────────────────────────────────────

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


# ─── Rewrite PLAT Package Name on Sync PLAT ─────────────────────────────────

def _rewrite_flag_from_db(db: Session | None) -> bool:
    """Read rewrite toggle; new key wins, else legacy aqua_recheck_on_sync."""

    def _read(session: Session) -> bool:
        row = session.get(PortalSetting, REWRITE_PLAT_PACKAGE_NAME_ON_SYNC_KEY)
        if row and (row.value or "").strip():
            return row.value.strip() == "1"
        legacy = session.get(PortalSetting, AQUA_RECHECK_ON_SYNC_KEY)
        if legacy and (legacy.value or "").strip():
            return legacy.value.strip() == "1"
        return False

    if db is not None:
        return _read(db)
    from api.app.db import db_session
    with db_session() as session:
        return _read(session)


def get_rewrite_plat_package_name_on_sync(db: Session | None = None) -> bool:
    """Whether sync_plat_for_run should rewrite Package Name on linked PLAT CVE tickets."""
    return _rewrite_flag_from_db(db)


def set_rewrite_plat_package_name_on_sync(db: Session, enabled: bool) -> bool:
    _set_str(db, REWRITE_PLAT_PACKAGE_NAME_ON_SYNC_KEY, "1" if enabled else "0")
    return enabled


def get_aqua_recheck_on_sync(db: Session | None = None) -> bool:
    """Deprecated alias — use get_rewrite_plat_package_name_on_sync."""
    return get_rewrite_plat_package_name_on_sync(db)


def set_aqua_recheck_on_sync(db: Session, enabled: bool) -> bool:
    """Deprecated alias — use set_rewrite_plat_package_name_on_sync."""
    return set_rewrite_plat_package_name_on_sync(db, enabled)


# ─── Preferred registry ───────────────────────────────────────────────────────

def get_aqua_preferred_registry(db: Session | None = None) -> str:
    """Aqua registry name to prefer when an image exists in multiple registries."""
    default = (settings.aqua_preferred_registry or "").strip()
    return _get_str(db, AQUA_PREFERRED_REGISTRY_KEY, default)


def set_aqua_preferred_registry(db: Session, value: str) -> str:
    return _set_str(db, AQUA_PREFERRED_REGISTRY_KEY, value.strip())


# ─── Default image tag ────────────────────────────────────────────────────────

def get_aqua_default_image_tag(db: Session | None = None) -> str:
    """Fallback Aqua image tag when the ticket's tag is not found in Aqua."""
    default = (settings.aqua_default_image_tag or "latest").strip() or "latest"
    return _get_str(db, AQUA_DEFAULT_IMAGE_TAG_KEY, default) or "latest"


def set_aqua_default_image_tag(db: Session, value: str) -> str:
    return _set_str(db, AQUA_DEFAULT_IMAGE_TAG_KEY, (value.strip() or "latest"))
