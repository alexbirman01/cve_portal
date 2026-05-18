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
    """Return lowercase set of all allowed basenames for O(1) lookup."""
    from api.app.models import AllowedImage

    rows = db.query(AllowedImage).all()
    return {r.name.lower() for r in rows}


def is_allowed_basename(name: str, allowed: set[str]) -> bool:
    return name.lower() in allowed
