"""Red Hat Security API client — fallback CVE enrichment when NVD is pending analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential


_RH_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "important": "HIGH",
    "moderate": "MEDIUM",
    "low": "LOW",
}

_PKG_VERSION_RE = re.compile(r"^(.+?)-(\d[\w.+~^]*)$")


@dataclass
class RedHatCve:
    cve_id: str
    severity: str | None
    score: str | None
    packages: list[dict[str, Any]] = field(default_factory=list)


class RedHatClient:
    _BASE = "https://access.redhat.com/hydra/rest/securitydata/cve"

    def __init__(self) -> None:
        self._client = httpx.Client(
            headers={"Accept": "application/json"},
            timeout=20.0,
        )

    def close(self) -> None:
        self._client.close()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=0.5, min=0.5, max=6))
    def fetch_cve(self, cve_id: str) -> RedHatCve | None:
        url = f"{self._BASE}/{cve_id}.json"
        try:
            r = self._client.get(url)
        except Exception:
            return None
        if r.status_code == 404:
            return None
        if not r.is_success:
            return None
        try:
            data = r.json()
        except Exception:
            return None
        return RedHatCve(
            cve_id=cve_id,
            severity=_normalize_severity(data.get("threat_severity")),
            score=_extract_score(data),
            packages=_parse_rh_packages(data),
        )


def _normalize_severity(raw: Any) -> str | None:
    if not raw:
        return None
    return _RH_SEVERITY_MAP.get(str(raw).strip().lower())


def _extract_score(data: dict[str, Any]) -> str | None:
    cvss3 = data.get("cvss3") or {}
    s = (cvss3.get("cvss3_base_score") or "").strip()
    return s if s else None


def _parse_rh_packages(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Build a package list compatible with the NVD packages dict shape:
    {"vendor": str, "product": str, "version_start": None, "fixed_version": str|None}

    Prefer affected_release entries (they carry a specific fix package string),
    falling back to package_state entries (package name only, no version).
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    for rel in data.get("affected_release") or []:
        pkg_str = (rel.get("package") or "").strip()
        if not pkg_str:
            continue
        product, fixed_version = _split_pkg_name_version(pkg_str)
        key = product.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "vendor": "redhat",
            "product": product,
            "version_start": None,
            "fixed_version": fixed_version,
        })

    if not out:
        for state in data.get("package_state") or []:
            pkg_name = (state.get("package_name") or "").strip()
            if not pkg_name:
                continue
            key = pkg_name.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "vendor": "redhat",
                "product": pkg_name,
                "version_start": None,
                "fixed_version": None,
            })

    return out


def _split_pkg_name_version(pkg_str: str) -> tuple[str, str | None]:
    """
    Split a Red Hat package string like `gnutls-main-3.8.13-1.hum1` into
    (name, version).  The version starts at the first segment that begins
    with a digit after a hyphen, e.g. `3.8.13-1.hum1`.
    Name portion: everything before that segment.
    """
    parts = pkg_str.split("-")
    for i, part in enumerate(parts):
        if i > 0 and part and part[0].isdigit():
            name = "-".join(parts[:i])
            version = "-".join(parts[i:])
            return name, version
    return pkg_str, None
