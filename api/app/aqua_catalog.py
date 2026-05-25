"""API helpers for browsing cached Aqua package catalogs."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from api.app.config import settings
from api.app.aqua_packages import catalog_fresh
from api.app.db import db_session
from api.app.models import AquaImagePackages
from api.app.portal_settings import get_aqua_packages_ttl_hours, set_aqua_packages_ttl_hours


class AquaPackagesSettingsIn(BaseModel):
    ttl_hours: int = Field(ge=1, le=8760)


class AquaPackagesRefreshIn(BaseModel):
    registry: str
    repository: str
    tag: str


def _iso_z(ts: dt.datetime | None) -> str | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.UTC)
    return ts.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def _image_summary(row: AquaImagePackages, ttl_hours: int) -> dict[str, Any]:
    fresh = catalog_fresh(row.fetched_at, ttl_hours=ttl_hours)
    try:
        packages = json.loads(row.packages_json or "[]")
        count = len(packages) if isinstance(packages, list) else 0
    except json.JSONDecodeError:
        count = 0
    return {
        "registry": row.registry,
        "repository": row.repository,
        "tag": row.tag,
        "display": f"{row.repository}:{row.tag}",
        "package_count": count,
        "fetched_at": _iso_z(row.fetched_at),
        "fresh": fresh,
    }


def list_aqua_package_catalog() -> dict[str, Any]:
    aqua_configured = bool((settings.aqua_api_key or "").strip())
    with db_session() as db:
        ttl_hours = get_aqua_packages_ttl_hours(db)
        rows = db.scalars(
            select(AquaImagePackages).order_by(
                AquaImagePackages.repository,
                AquaImagePackages.tag,
            )
        ).all()
        images = [_image_summary(r, ttl_hours) for r in rows]
    return {
        "aqua_configured": aqua_configured,
        "ttl_hours": ttl_hours,
        "default_ttl_hours": max(1, int(settings.aqua_packages_ttl_hours or 168)),
        "images": images,
    }


def get_aqua_package_entry(registry: str, repository: str, tag: str) -> dict[str, Any]:
    reg = registry.strip()
    repo = repository.strip()
    t = tag.strip()
    if not reg or not repo or not t:
        raise HTTPException(status_code=400, detail="registry, repository, and tag required")
    with db_session() as db:
        ttl_hours = get_aqua_packages_ttl_hours(db)
        row = db.get(AquaImagePackages, {"registry": reg, "repository": repo, "tag": t})
        if not row:
            raise HTTPException(status_code=404, detail="catalog not found")
        try:
            packages = json.loads(row.packages_json or "[]")
            if not isinstance(packages, list):
                packages = []
        except json.JSONDecodeError:
            packages = []
        summary = _image_summary(row, ttl_hours)
        return {**summary, "packages": packages}


def get_aqua_packages_settings() -> dict[str, Any]:
    with db_session() as db:
        ttl_hours = get_aqua_packages_ttl_hours(db)
    return {
        "ttl_hours": ttl_hours,
        "default_ttl_hours": max(1, int(settings.aqua_packages_ttl_hours or 168)),
        "aqua_configured": bool((settings.aqua_api_key or "").strip()),
    }


def patch_aqua_packages_settings(payload: AquaPackagesSettingsIn) -> dict[str, Any]:
    with db_session() as db:
        ttl_hours = set_aqua_packages_ttl_hours(db, payload.ttl_hours)
    return {"ok": True, "ttl_hours": ttl_hours}


def delete_aqua_cache_entry(registry: str, repository: str, tag: str) -> dict[str, bool]:
    reg = registry.strip()
    repo = repository.strip()
    t = tag.strip()
    with db_session() as db:
        row = db.get(AquaImagePackages, {"registry": reg, "repository": repo, "tag": t})
        if not row:
            raise HTTPException(status_code=404, detail="catalog not found")
        db.delete(row)
        db.commit()
    return {"ok": True}


def refresh_aqua_cache_entry(payload: AquaPackagesRefreshIn) -> dict[str, Any]:
    if not (settings.aqua_api_key or "").strip():
        raise HTTPException(status_code=400, detail="Aqua API not configured")
    reg = payload.registry.strip()
    repo = payload.repository.strip()
    t = payload.tag.strip()
    if not reg or not repo or not t:
        raise HTTPException(status_code=400, detail="registry, repository, and tag required")
    from api.app.aqua_client import AquaClient, AquaImageRef
    from api.app.aqua_packages import _save_catalog

    aqua = AquaClient()
    try:
        image_ref = AquaImageRef(registry=reg, repository=repo, tag=t)
        packages = aqua.fetch_all_resources(image_ref)
        with db_session() as db:
            _save_catalog(db, image_ref, packages)
            ttl_hours = get_aqua_packages_ttl_hours(db)
            row = db.get(AquaImagePackages, {"registry": reg, "repository": repo, "tag": t})
            if not row:
                raise HTTPException(status_code=404, detail="refresh failed")
            return _image_summary(row, ttl_hours)
    finally:
        aqua.close()
