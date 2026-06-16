"""Alpine Linux package enrichment via OSV (Alpine secdb)."""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential


def _ver_tuple(v: str | None) -> tuple:
    if not v:
        return ()
    parts: list[int | str] = []
    for seg in v.replace("-", ".").split("."):
        seg = seg.strip()
        if not seg:
            continue
        if seg.isdigit():
            parts.append(int(seg))
        else:
            parts.append(seg)
    return tuple(parts)


def parse_osv_alpine_packages(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse OSV vuln JSON into shared package dicts:
      {"vendor": "alpine", "product": str, "version_start": None, "fixed_version": str|None}
    """
    seen: dict[str, dict[str, Any]] = {}
    for aff in data.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        eco = (pkg.get("ecosystem") or "").strip().lower()
        if not eco.startswith("alpine"):
            continue
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        fixed_ver: str | None = None
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            if (rng.get("type") or "").strip() != "ECOSYSTEM":
                continue
            for ev in rng.get("events") or []:
                if not isinstance(ev, dict):
                    continue
                fx = (ev.get("fixed") or "").strip()
                if fx:
                    fixed_ver = fx
        key = name.lower()
        existing = seen.get(key)
        if not existing or _ver_tuple(fixed_ver) > _ver_tuple(existing.get("fixed_version")):
            seen[key] = {
                "vendor": "alpine",
                "product": name,
                "version_start": None,
                "fixed_version": fixed_ver,
            }
    return list(seen.values())


class AlpineClient:
    _BASE = "https://api.osv.dev/v1/vulns"

    def __init__(self) -> None:
        self._client = httpx.Client(
            headers={"Accept": "application/json"},
            timeout=20.0,
        )

    def close(self) -> None:
        self._client.close()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=0.5, min=0.5, max=6))
    def fetch_cve_packages(self, cve_id: str) -> list[dict[str, Any]]:
        """Return Alpine package rows for a CVE, or [] when not in secdb/OSV."""
        cve = (cve_id or "").strip().upper()
        if not cve.startswith("CVE-"):
            return []
        vuln_id = f"ALPINE-{cve}"
        try:
            r = self._client.get(f"{self._BASE}/{vuln_id}")
        except Exception:
            return []
        if r.status_code == 404:
            return []
        if not r.is_success:
            return []
        try:
            data = r.json()
        except Exception:
            return []
        if not isinstance(data, dict):
            return []
        return parse_osv_alpine_packages(data)
