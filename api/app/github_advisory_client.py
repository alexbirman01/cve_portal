"""GitHub Security Advisory (GHSA) client — enrichment for GHSA-only findings."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from api.app.config import settings


@dataclass
class GithubAdvisory:
    ghsa_id: str
    state: str  # ok | not_found | error
    cve_id: str | None = None
    severity: str | None = None
    score: str | None = None
    published: str | None = None
    modified: str | None = None
    summary: str | None = None
    packages: list[dict[str, Any]] = field(default_factory=list)
    raw_json: str | None = None


class GithubAdvisoryClient:
    _BASE = "https://api.github.com/advisories"

    def __init__(self) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = (getattr(settings, "github_token", None) or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(headers=headers, timeout=20.0)

    def close(self) -> None:
        self._client.close()

    @retry(stop_after_attempt(3), wait=wait_exponential(multiplier=0.5, min=0.5, max=6))
    def fetch(self, ghsa_id: str) -> GithubAdvisory:
        gid = (ghsa_id or "").strip().upper()
        if not gid.startswith("GHSA-"):
            return GithubAdvisory(ghsa_id=gid, state="error")
        url = f"{self._BASE}/{gid.lower()}"
        try:
            r = self._client.get(url)
        except Exception:
            return GithubAdvisory(ghsa_id=gid, state="error")
        if r.status_code == 404:
            return GithubAdvisory(ghsa_id=gid, state="not_found")
        if not r.is_success:
            return GithubAdvisory(ghsa_id=gid, state="error")
        try:
            data = r.json()
        except Exception:
            return GithubAdvisory(ghsa_id=gid, state="error")

        cve_alias = (data.get("cve_id") or "").strip().upper() or None
        severity = (data.get("severity") or "").strip().lower() or None
        if severity:
            severity = severity.upper()

        score = None
        cvss = data.get("cvss") or {}
        if isinstance(cvss, dict) and cvss.get("score") not in (None, 0, 0.0):
            score = str(cvss["score"])
        else:
            sevs = data.get("cvss_severities") or {}
            for key in ("cvss_v3", "cvss_v4"):
                block = sevs.get(key) or {}
                if isinstance(block, dict) and block.get("score") not in (None, 0, 0.0):
                    score = str(block["score"])
                    break

        packages: list[dict[str, Any]] = []
        for vuln in data.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            pkg = vuln.get("package") or {}
            name = (pkg.get("name") or "").strip()
            if not name:
                continue
            packages.append(
                {
                    "vendor": (pkg.get("ecosystem") or "").strip() or None,
                    "product": name,
                    "version_start": None,
                    "fixed_version": (vuln.get("first_patched_version") or None),
                }
            )

        return GithubAdvisory(
            ghsa_id=gid,
            state="ok",
            cve_id=cve_alias,
            severity=severity,
            score=score,
            published=data.get("published_at"),
            modified=data.get("updated_at"),
            summary=data.get("summary"),
            packages=packages,
            raw_json=json.dumps(data),
        )
