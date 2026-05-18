"""PLAT ticket discovery and linking scoped to CVE + image basename pairs."""

from __future__ import annotations

from typing import Any

from api.app.cve_row_derived import image_basenames_for_cve_row
from api.app.jira_client import JiraClient, _image_basename_from_summary


def plat_keys_to_link_for_row(jira: JiraClient, row: dict[str, Any]) -> list[str]:
    """
    PLAT keys to link to the parent PLATFORM ticket for this row.
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
        for pk in jira.find_plat_bug_for_image(cve_id, bn):
            low = pk.strip().upper()
            if low and low not in seen:
                seen.add(low)
                out.append(pk.strip())
    return out


def plat_tickets_for_row(
    cve_id: str,
    raw_plat: list[dict[str, Any]],
    row: dict[str, Any],
    bug_items: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """
    PLAT tickets to store on a CVE row for display.
    Security Vulns: all from raw_plat. Bugs: only those matching an extracted image basename.
    """
    want = {bn.casefold() for bn in image_basenames_for_cve_row(row)}
    sec = [t for t in raw_plat if t.get("issue_type") == "Security Vulnerability"]
    if not want:
        return sec

    raw_by_key = {str(t["key"]): t for t in raw_plat if t.get("key")}
    bugs: list[dict[str, Any]] = []
    seen_bug: set[str] = set()

    if bug_items is not None:
        for item in bug_items:
            bn = (item.get("image_basename") or "").strip()
            if not bn or bn.casefold() not in want:
                continue
            key = (item.get("key") or "").strip()
            if not key:
                continue
            ku = key.upper()
            if ku in seen_bug:
                continue
            seen_bug.add(ku)
            t = raw_by_key.get(key)
            if t:
                bugs.append(t)
            else:
                bugs.append(
                    {
                        "key": key,
                        "issue_type": "Bug",
                        "summary": f"[{cve_id}] - [{bn}]",
                    }
                )
        return sec + bugs

    for t in raw_plat:
        if t.get("issue_type") != "Bug":
            continue
        bn = _image_basename_from_summary(t.get("summary"), cve_id)
        if not bn or bn.casefold() not in want:
            continue
        key = (t.get("key") or "").strip()
        if not key:
            continue
        ku = key.upper()
        if ku in seen_bug:
            continue
        seen_bug.add(ku)
        bugs.append(t)
    return sec + bugs
