"""PLAT ticket discovery and linking scoped to CVE + image basename pairs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from api.app.cve_row_derived import image_basenames_for_cve_row

if TYPE_CHECKING:
    from api.app.jira_client import JiraClient


def filter_plat_hits_for_image(
    search_results: list[dict[str, str]],
    image_basename: str,
) -> list[str]:
    """PLAT keys whose parsed image_basename matches (casefold)."""
    want = image_basename.strip().casefold()
    if not want:
        return []
    return [
        item["key"]
        for item in search_results
        if item.get("key") and (item.get("image_basename") or "").strip().casefold() == want
    ]


def plat_security_by_image_from_search(
    search_results: list[dict[str, str]],
) -> tuple[dict[str, list[str]], list[str]]:
    """Build image→keys map and list keys with unparseable image basename."""
    by_img: dict[str, list[str]] = {}
    unmapped: list[str] = []
    for item in search_results:
        key = (item.get("key") or "").strip()
        if not key:
            continue
        img = (item.get("image_basename") or "").strip()
        if not img:
            unmapped.append(key)
            continue
        by_img.setdefault(img, []).append(key)
    return by_img, unmapped


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


def link_plat_key_to_parent(
    jira: JiraClient,
    plat_key: str,
    source_issue_key: str,
    seen: set[str],
    counts: dict[str, Any],
) -> None:
    """Relates-link one PLAT to PLATFORM and append Organization from the parent.

    Org merge is idempotent and non-fatal (same helper as Create PLAT reuse).
    Mutates ``seen`` and ``counts`` (links_checked, links_created, orgs_merged, errors).
    """
    pk = (plat_key or "").strip().upper()
    if not pk or pk in seen:
        return
    seen.add(pk)
    result = jira.ensure_plat_linked_to_parent(pk, source_issue_key)
    counts["links_checked"] = int(counts.get("links_checked") or 0) + 1
    if result.created:
        counts["links_created"] = int(counts.get("links_created") or 0) + 1
    elif result.error_warning:
        errors = counts.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(result.error_warning)
    try:
        # organization_refs=None → copy/merge from PLATFORM via existing Jira settings.
        if jira.merge_organization_on_issue(pk, None, source_issue_key):
            counts["orgs_merged"] = int(counts.get("orgs_merged") or 0) + 1
    except Exception as exc:
        errors = counts.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(f"org merge on {pk}: {exc}")
