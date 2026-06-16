"""PLAT ticket discovery and linking scoped to CVE + image basename pairs."""

from __future__ import annotations

from typing import Any

from api.app.cve_row_derived import image_basenames_for_cve_row
from api.app.jira_client import JiraClient


def plat_keys_to_link_for_row(jira: JiraClient, row: dict[str, Any]) -> list[str]:
    """
    Security Vulnerability PLAT keys to link to the parent PLATFORM ticket for this row.
    One Jira lookup per extracted (cve_id, image_basename); exact basename match only.
    """
    cve_id = str(row.get("cve_id") or "").strip()
    if not cve_id:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for bn in image_basenames_for_cve_row(row):
        for pk in jira.find_plat_security_for_image(cve_id, bn):
            low = pk.strip().upper()
            if low and low not in seen:
                seen.add(low)
                out.append(pk.strip())
    return out


def plat_tickets_for_row(
    cve_id: str,
    raw_plat: list[dict[str, Any]],
    row: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Security Vulnerability PLAT tickets to store on a CVE row for display.
    """
    return [t for t in raw_plat if t.get("issue_type") == "Security Vulnerability"]
