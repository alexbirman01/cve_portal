"""Helpers for the allowed_images catalog."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def normalize_image_basename(path_or_name: str) -> str:
    """Strip plainid/ prefix, take last path segment, lowercase."""
    s = path_or_name.replace("plainid/", "").replace("PLAINID/", "")
    parts = s.strip().split("/")
    return parts[-1].strip().lower() if parts else ""


def load_allowed_names(db: "Session") -> set[str]:
    """Return lowercase set of all allowed basenames (names + aliases) for O(1) lookup."""
    from api.app.models import AllowedImage

    rows = db.query(AllowedImage).all()
    names: set[str] = set()
    for r in rows:
        names.add(r.name.lower())
        for alias in (r.aliases or "").split(","):
            a = alias.strip().lower()
            if a:
                names.add(a)
    return names


def load_alias_map(db: "Session") -> dict[str, str]:
    """Map every known token (name + aliases, lowercased) → canonical lowercase name.

    Used by the Aqua JSON parser and worker to resolve vendor-specific image identifiers
    (e.g. 'secretmgr', 'sqlauth') to the canonical PlainID basename (e.g. 'secrets-mgmt').
    """
    from api.app.models import AllowedImage

    out: dict[str, str] = {}
    for row in db.query(AllowedImage).all():
        canonical = row.name.lower().strip()
        out[canonical] = canonical
        for alias in (row.aliases or "").split(","):
            a = alias.strip().lower()
            if a:
                out[a] = canonical
    return out


def is_allowed_basename(name: str, allowed: set[str]) -> bool:
    return name.lower() in allowed
