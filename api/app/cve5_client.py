"""MITRE CVE 5.0 API client — authoritative CNA version data.

Supplements NVD and Red Hat when those sources lack package-level version
ranges.  The CVE 5.0 format carries structured version info directly from
the CVE Numbering Authority (CNA), which NVD's CPE layer sometimes drops.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class Cve5Result:
    cve_id: str
    packages: list[dict[str, Any]] = field(default_factory=list)


class Cve5Client:
    _BASE = "https://cveawg.mitre.org/api/cve"

    def __init__(self) -> None:
        self._client = httpx.Client(
            headers={"Accept": "application/json"},
            timeout=20.0,
        )

    def close(self) -> None:
        self._client.close()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=0.5, min=0.5, max=6))
    def fetch_cve(self, cve_id: str) -> Cve5Result | None:
        url = f"{self._BASE}/{cve_id}"
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
        return Cve5Result(
            cve_id=cve_id,
            packages=_parse_cve5_packages(data),
        )


def _parse_cve5_packages(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse containers.cna.affected[] into the shared package dict shape:
      {"vendor": str, "product": str, "version_start": str|None, "fixed_version": str|None}

    CVE 5.0 version block patterns:
      A) defaultStatus="unaffected", versions=[{status:"affected", version:"X", lessThan:"Y"}]
         → affected range [X, Y), fixed_version = Y, version_start = X unless "0"
      B) defaultStatus="affected", versions=[{status:"unaffected", version:"Y", lessThan:"*"}]
         → all versions up to Y affected, fixed_version = Y
    """
    cna = (data.get("containers") or {}).get("cna") or {}
    affected_list: list[dict] = cna.get("affected") or []

    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    for entry in affected_list:
        pkg_name = (entry.get("packageName") or "").strip()
        if not pkg_name:
            continue

        vendor = (entry.get("vendor") or "").strip() or None
        default_status = (entry.get("defaultStatus") or "").lower()
        versions: list[dict] = entry.get("versions") or []

        version_start: str | None = None
        fixed_version: str | None = None

        if default_status == "unaffected":
            # Find the affected range → lessThan is the fix boundary
            for v in versions:
                if (v.get("status") or "").lower() == "affected":
                    raw_start = (v.get("version") or "").strip()
                    # "0" is a semver placeholder meaning "from the very beginning"
                    if raw_start and raw_start not in ("0", "0.0", "0.0.0", "*", "-", ""):
                        version_start = raw_start
                    fixed_version = (
                        v.get("lessThan") or v.get("lessThanOrEqual") or ""
                    ).strip() or None
                    break
        else:
            # defaultStatus="affected" — find the first unaffected version = the fix
            for v in versions:
                if (v.get("status") or "").lower() == "unaffected":
                    raw_fix = (v.get("version") or "").strip()
                    if raw_fix and raw_fix not in ("*", "-", ""):
                        fixed_version = raw_fix
                    break

        if not fixed_version and not version_start:
            continue

        key = pkg_name.lower()
        if key in seen:
            continue
        seen.add(key)

        out.append({
            "vendor": vendor or "unknown",
            "product": pkg_name,
            "version_start": version_start,
            "fixed_version": fixed_version,
        })

    return out
