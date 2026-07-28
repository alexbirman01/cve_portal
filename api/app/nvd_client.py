from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from api.app.config import settings


@dataclass(frozen=True)
class AffectedPackage:
    vendor: str
    product: str
    version_start: str | None   # first affected version (inclusive)
    fixed_version: str | None   # first fixed version (versionEndExcluding)


@dataclass(frozen=True)
class NvdCve:
    cve_id: str
    state: str  # ok | not_found | error
    severity: str | None
    score: str | None
    published: str | None
    modified: str | None
    raw_json: str | None
    affected_packages: list[AffectedPackage] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        # Ensure the field is always a list even when not provided.
        if self.affected_packages is None:
            object.__setattr__(self, "affected_packages", [])


class NvdClient:
    def __init__(self) -> None:
        headers = {"Accept": "application/json"}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        self._client = httpx.Client(headers=headers, timeout=30.0)

    def close(self) -> None:
        self._client.close()

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=0.5, min=0.5, max=8))
    def fetch_cve(self, cve_id: str) -> NvdCve:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        r = self._client.get(url, params={"cveId": cve_id})
        if r.status_code == 404:
            return NvdCve(cve_id=cve_id, state="not_found", severity=None, score=None, published=None, modified=None, raw_json=None)
        r.raise_for_status()
        data = r.json()
        cves = data.get("vulnerabilities") or []
        if not cves:
            return NvdCve(cve_id=cve_id, state="not_found", severity=None, score=None, published=None, modified=None, raw_json=None)

        cve = (cves[0] or {}).get("cve") or {}
        published = cve.get("published")
        modified = cve.get("lastModified")
        severity, score = _extract_cvss(cve.get("metrics") or {})
        affected_packages = _extract_affected_packages(cve)

        return NvdCve(
            cve_id=cve_id,
            state="ok",
            severity=severity,
            score=score,
            published=published,
            modified=modified,
            raw_json=json.dumps(data),
            affected_packages=affected_packages,
        )


def _extract_affected_packages(cve_data: dict[str, Any]) -> list[AffectedPackage]:
    """Parse NVD configurations/cpeMatch entries into structured package records."""
    packages: list[AffectedPackage] = []
    seen: set[tuple] = set()

    for config in cve_data.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria: str = match.get("criteria", "")
                # cpe:2.3:type:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) < 5:
                    continue
                vendor = parts[3]
                product = parts[4]
                version_start = (
                    match.get("versionStartIncluding")
                    or match.get("versionStartExcluding")
                )
                fixed_version = (
                    match.get("versionEndExcluding")
                    or match.get("versionEndIncluding")
                )
                # For exact CPE matches (no range fields), the affected version
                # is encoded directly in the CPE string at parts[5].
                # e.g. cpe:2.3:a:oracle:jre:1.8.0:update481:... → "1.8.0"
                if not version_start and not fixed_version and len(parts) > 5:
                    inline_ver = parts[5]
                    if inline_ver not in ("*", "-", ""):
                        version_start = inline_ver
                key = (vendor, product, version_start, fixed_version)
                if key in seen:
                    continue
                seen.add(key)
                packages.append(
                    AffectedPackage(
                        vendor=vendor,
                        product=product,
                        version_start=version_start,
                        fixed_version=fixed_version,
                    )
                )
    return packages


def _extract_cvss(metrics: dict[str, Any]) -> tuple[str | None, str | None]:
    # Prefer v3.1, then v3.0, then v4.0, then v2.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        arr = metrics.get(key)
        if not arr or not isinstance(arr, list):
            continue
        first = arr[0] or {}
        cvss = first.get("cvssData") or {}
        severity = cvss.get("baseSeverity") or first.get("baseSeverity")
        score = cvss.get("baseScore") or first.get("baseScore")
        if severity is not None or score is not None:
            return (str(severity) if severity is not None else None, str(score) if score is not None else None)
    return (None, None)

