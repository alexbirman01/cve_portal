"""Aqua package catalog cache + substring matching."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from api.app.aqua_client import AquaClient, AquaImageRef
from api.app.config import settings
from api.app.models import AquaImagePackages
from api.app.portal_settings import get_aqua_packages_ttl_hours


@dataclass
class AquaPackageCandidate:
    name: str
    version: str | None
    source: str  # customer | nvd | aqua


@dataclass
class AquaCrossCheckResult:
    found: bool
    aqua_package_name: str | None = None
    aqua_package_version: str | None = None
    candidates: list[AquaPackageCandidate] = field(default_factory=list)
    aqua_checked: bool = False
    """Ticket/Jira tag when catalog was loaded from a different Aqua tag (e.g. latest)."""
    aqua_tag_requested: str | None = None
    aqua_tag_used: str | None = None


def _resolve_image_ref(
    aqua: AquaClient,
    repository: str,
    tag: str,
) -> AquaImageRef | None:
    """Resolve image in Aqua; fall back to default tag when the requested tag is not registered."""
    ref = aqua.resolve_image(repository, tag)
    if ref:
        return ref
    fallback = (settings.aqua_default_image_tag or "latest").strip() or "latest"
    if tag.lower() == fallback.lower():
        return None
    return aqua.resolve_image(repository, fallback)


def repository_for_basename(image_basename: str) -> str:
    bn = (image_basename or "").strip().lower()
    if not bn:
        return ""
    if "/" in bn:
        return bn
    return f"plainid/{bn}"


def catalog_fresh(fetched_at: dt.datetime | None, *, ttl_hours: int | None = None) -> bool:
    if fetched_at is None:
        return False
    ttl_h = max(1, int(ttl_hours if ttl_hours is not None else get_aqua_packages_ttl_hours()))
    age = dt.datetime.now(dt.UTC) - fetched_at
    return age.total_seconds() < ttl_h * 3600


def _catalog_fresh(fetched_at: dt.datetime | None) -> bool:
    return catalog_fresh(fetched_at)


def _load_catalog_row(db: Session, registry: str, repository: str, tag: str) -> list[dict[str, Any]] | None:
    row = db.get(
        AquaImagePackages,
        {"registry": registry, "repository": repository, "tag": tag},
    )
    if not row or not _catalog_fresh(row.fetched_at):
        return None
    try:
        data = json.loads(row.packages_json or "[]")
        return data if isinstance(data, list) else None
    except json.JSONDecodeError:
        return None


def _save_catalog(
    db: Session,
    image: AquaImageRef,
    packages: list[dict[str, str]],
) -> None:
    key = {"registry": image.registry, "repository": image.repository, "tag": image.tag}
    row = db.get(AquaImagePackages, key)
    payload = json.dumps(packages)
    now = dt.datetime.now(dt.UTC)
    if row:
        row.packages_json = payload
        row.fetched_at = now
    else:
        row = AquaImagePackages(
            registry=image.registry,
            repository=image.repository,
            tag=image.tag,
            packages_json=payload,
            fetched_at=now,
        )
        db.add(row)
    db.commit()


def get_or_fetch_image_packages(
    db: Session,
    image_basename: str,
    tag: str | None = None,
    *,
    force_refresh: bool = False,
    client: AquaClient | None = None,
) -> tuple[list[dict[str, Any]], AquaImageRef | None]:
    """
    Return (catalog, image_ref). Empty catalog if Aqua not configured or image not in Aqua.
    """
    if not (settings.aqua_api_key or "").strip():
        return [], None

    repository = repository_for_basename(image_basename)
    if not repository:
        return [], None

    requested_tag = (tag or "").strip() or settings.aqua_default_image_tag.strip() or "latest"
    own_client = client is None
    aqua = client or AquaClient()
    try:
        image_ref = _resolve_image_ref(aqua, repository, requested_tag)
        if not image_ref:
            return [], None

        if not force_refresh:
            cached = _load_catalog_row(db, image_ref.registry, image_ref.repository, image_ref.tag)
            if cached is not None:
                return cached, image_ref

        packages = aqua.fetch_all_resources(image_ref)
        _save_catalog(db, image_ref, packages)
        return packages, image_ref
    finally:
        if own_client:
            aqua.close()


def _match_score(search: str, aqua_name: str) -> int:
    """Higher is better; 0 = no match."""
    s = search.strip()
    a = aqua_name.strip()
    if not s or not a:
        return 0
    if s == a:
        return 3
    sl, al = s.lower(), a.lower()
    if sl == al:
        return 3
    if al in sl or sl in al:
        return 2 if al in sl else 1
    return 0


def _best_catalog_match(
    catalog: list[dict[str, Any]],
    search_name: str,
) -> dict[str, Any] | None:
    search = (search_name or "").strip()
    if not search or not catalog:
        return None
    best: dict[str, Any] | None = None
    best_score = 0
    for pkg in catalog:
        name = str(pkg.get("name") or "").strip()
        sc = _match_score(search, name)
        if sc > best_score:
            best_score = sc
            best = pkg
    return best if best_score > 0 else None


def _aqua_hint_from_catalog(catalog: list[dict[str, Any]], search_name: str) -> str | None:
    """Catalog name that substring-overlaps search; None if nothing related (no arbitrary first row)."""
    search = (search_name or "").strip().lower()
    if not search:
        return None
    exact = _best_catalog_match(catalog, search_name)
    if exact:
        return str(exact.get("name") or "")
    for pkg in catalog:
        name = str(pkg.get("name") or "").strip()
        nl = name.lower()
        if search in nl or nl in search:
            return name
    return None


def match_package_in_catalog(
    catalog: list[dict[str, Any]],
    search_name: str,
    *,
    customer_name: str | None = None,
    nvd_name: str | None = None,
) -> AquaCrossCheckResult:
    if not (search_name or "").strip():
        return AquaCrossCheckResult(found=False, aqua_checked=True)

    hit = _best_catalog_match(catalog, search_name)
    if hit:
        return AquaCrossCheckResult(
            found=True,
            aqua_package_name=str(hit.get("name") or ""),
            aqua_package_version=hit.get("version"),
            aqua_checked=True,
        )

    candidates: list[AquaPackageCandidate] = []
    seen: set[str] = set()

    def add(name: str | None, source: str) -> None:
        n = (name or "").strip()
        if not n:
            return
        k = n.lower()
        if k in seen:
            return
        seen.add(k)
        candidates.append(AquaPackageCandidate(name=n, version=None, source=source))

    add(customer_name or search_name, "customer")
    add(nvd_name, "nvd")
    aqua_hint = _aqua_hint_from_catalog(catalog, search_name)
    add(aqua_hint, "aqua")

    return AquaCrossCheckResult(
        found=False,
        candidates=candidates[:3],
        aqua_checked=True,
    )


def cross_check_package(
    db: Session,
    image_basename: str,
    search_name: str,
    *,
    tag: str | None = None,
    customer_name: str | None = None,
    nvd_name: str | None = None,
    force_refresh: bool = False,
    client: AquaClient | None = None,
) -> AquaCrossCheckResult:
    if not (settings.aqua_api_key or "").strip():
        return AquaCrossCheckResult(found=False, aqua_checked=False)

    requested_tag = (tag or "").strip() or settings.aqua_default_image_tag.strip() or "latest"
    catalog, image_ref = get_or_fetch_image_packages(
        db,
        image_basename,
        tag,
        force_refresh=force_refresh,
        client=client,
    )
    tag_fallback = (
        image_ref is not None
        and requested_tag.lower() != (image_ref.tag or "").lower()
    )
    if not catalog:
        candidates: list[AquaPackageCandidate] = []
        seen: set[str] = set()

        def add(name: str | None, source: str) -> None:
            n = (name or "").strip()
            if not n:
                return
            k = n.lower()
            if k in seen:
                return
            seen.add(k)
            candidates.append(AquaPackageCandidate(name=n, version=None, source=source))

        add(customer_name or search_name, "customer")
        add(nvd_name, "nvd")
        out = AquaCrossCheckResult(
            found=False,
            candidates=candidates[:3],
            aqua_checked=True,
        )
        if tag_fallback and image_ref:
            out.aqua_tag_requested = requested_tag
            out.aqua_tag_used = image_ref.tag
        return out

    cust = (customer_name or "").strip() or None
    nvd = (nvd_name or "").strip() or None
    if cust and cust.lower() == (nvd or "").lower():
        nvd = None
    out = match_package_in_catalog(
        catalog,
        search_name,
        customer_name=cust,
        nvd_name=nvd,
    )
    if tag_fallback and image_ref:
        out.aqua_tag_requested = requested_tag
        out.aqua_tag_used = image_ref.tag
    return out


def candidates_to_json(candidates: list[AquaPackageCandidate]) -> list[dict[str, Any]]:
    return [
        {"name": c.name, "version": c.version, "source": c.source}
        for c in candidates
    ]
