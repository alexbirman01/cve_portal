"""Case-insensitive GHSA matching for PLAT CVE-field search and summary/correlation."""

from __future__ import annotations

import re


def vuln_id_search_variants(cve_id: str) -> list[str]:
    """Return casings to match in Jira CVE/GHSA custom field equality.

    Portal normalizes findings to uppercase, but other processes may create PLAT
    tickets with GitHub's mixed form (`GHSA-` + lowercase hex), e.g.
    ``GHSA-hrxh-6v49-42gf``. CVE ids are matched as provided (conventionally uppercase).
    """
    raw = (cve_id or "").strip()
    if not raw:
        return []
    upper = raw.upper()
    if upper.startswith("GHSA-"):
        # GitHub / some creators: prefix stays GHSA-, hex is lowercase.
        github_form = "GHSA-" + upper[5:].lower()
        variants: list[str] = []
        for v in (upper, github_form):
            if v not in variants:
                variants.append(v)
        return variants
    return [raw]


def jql_cve_field_equals(cve_id: str, cfn: int) -> str:
    """JQL clause for cf[CVE] matching ``cve_id``, case-insensitive for GHSA."""
    variants = vuln_id_search_variants(cve_id)
    if not variants:
        return f'cf[{cfn}] = ""'
    if len(variants) == 1:
        return f'cf[{cfn}] = "{variants[0]}"'
    joined = ", ".join(f'"{v}"' for v in variants)
    return f"cf[{cfn}] IN ({joined})"


def image_basename_from_correlation(correlation_id: str | None, cve_id: str) -> str | None:
    if not correlation_id or not cve_id:
        return None
    cid = correlation_id.strip()
    suffix = "_" + cve_id.strip()
    if cid.casefold().endswith(suffix.casefold()):
        stem = cid[: -len(suffix)].strip()
        return stem or None
    return None


def image_basename_from_summary(summary: str | None, cve_id: str) -> str | None:
    if not summary or not cve_id:
        return None
    m = re.match(
        r"^\s*\[" + re.escape(cve_id.strip()) + r"\]\s*-\s*\[([^\]]+)\]\s*$",
        summary.strip(),
        re.IGNORECASE,
    )
    if m:
        s = m.group(1).strip()
        return s or None
    return None
