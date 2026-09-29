"""Server-side build of the customer status comment.

Mirrors buildCustomerStatusComment and its helpers in ui/src/api.ts so the daily
Celery job produces byte-identical text to the operator's manual push. The two
implementations must be changed together.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from api.app.cve_row_derived import (
    _comment_plat_raw_for_keys,
    _image_path_basename,
    _plat_orphan_sec_keys,
    _translate_fix_version_to_release_date,
    _normalize_plat_sync_field_value,
    cve_rows_from_result,
    image_basenames_for_cve_row,
    package_entry_for_image,
    plat_issue_status_invalid_for_keys,
    plat_issue_status_is_pending_vendor_fix,
    plat_sec_keys_for_image,
    plat_security_keys,
    release_code_from_fix_versions,
)
from api.app.package_name import canonical_single_package_name
from api.app.parsing import aqua_tag_version, severity_rank

IN_PROGRESS = "In progress"
NOTE = 'Note: The "Expected Release Date" is an estimate and may be subject to change.'

# (header, minimum width, row key) — mirrors COMMENT_COL_SPECS in api.ts.
_COL_SPECS: list[tuple[str, int, str]] = [
    ("CVE", 12, "cve"),
    ("Severity", 8, "severity"),
    ("Image", 5, "image"),
    ("Package", 7, "package_name"),
    ("Expected release date", 22, "expected_release"),
    ("Fix Version", 10, "fix_version"),
]


def format_report_date(today: dt.date | None = None) -> str:
    d = today or dt.date.today()
    return f"{d.strftime('%B')} {d.day}, {d.year}"


def build_customer_status_comment_intro(today: dt.date | None = None) -> list[str]:
    """Header lines before the table — mirrors formatCustomerStatusCommentIntro."""
    return [
        "This CVE report is updated daily.",
        f"Last updated: {format_report_date(today)}",
        "",
        NOTE,
        "",
    ]


def _severity_for_comment(row: dict[str, Any]) -> str:
    sev = str(row.get("severity") or "").strip()
    if not sev:
        return "Unknown"
    score = str(row.get("score") or "").strip()
    return f"{sev.upper()} ({score})" if score else sev.upper()


def _image_label(row: dict[str, Any], basename: str) -> str:
    """'basename:tag' using the display form of the tag — mirrors platDisplayLabelForImage."""
    fold = basename.lower()
    for img in row.get("affected_images") or []:
        image = str(img.get("image") or "")
        if image and image != "NA" and _image_path_basename(image).lower() == fold:
            tag = aqua_tag_version(str(img.get("tag") or ""))
            return f"{basename}:{tag}" if tag else basename
    ai = row.get("affected_image")
    if ai and ai != "NA" and _image_path_basename(str(ai)).lower() == fold:
        tag = aqua_tag_version(str(row.get("affected_tag") or ""))
        return f"{basename}:{tag}" if tag else basename
    version = str(row.get("affected_version") or "").strip()
    return f"{basename}:{version}" if version else basename


def _package_not_found(row: dict[str, Any], basename: str) -> bool:
    entry = package_entry_for_image(row, basename)
    if entry.get("aqua_checked") is not None:
        return entry.get("aqua_pkg_found") is not True
    if row.get("aqua_pkg_found") is not None:
        return row.get("aqua_pkg_found") is not True
    return False


def _package_name(row: dict[str, Any], basename: str) -> str:
    entry = package_entry_for_image(row, basename)
    name = canonical_single_package_name(
        entry.get("aqua_package_name")
        or entry.get("affected_resource")
        or row.get("affected_resource")
    )
    return name or "—"


def _release_version(fix: str, tag: str) -> str:
    """Release code straight off the fix-version name, so stale runs are right without a re-sync."""
    from_fix = release_code_from_fix_versions(_normalize_plat_sync_field_value(fix))
    return from_fix or _normalize_plat_sync_field_value(tag) or IN_PROGRESS


def _expected_release_for_comment(fix: str, tag: str) -> str:
    """Only a real translated date, never the raw version name — this goes to the customer."""
    for raw in (_normalize_plat_sync_field_value(fix), _normalize_plat_sync_field_value(tag)):
        if raw:
            date = _translate_fix_version_to_release_date(raw)
            if date:
                return date
    return IN_PROGRESS


def _sorted_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Severity first (most severe first), then CVE id — mirrors sortCveRows."""
    return sorted(
        rows,
        key=lambda r: (-severity_rank(r.get("severity")), str(r.get("cve_id") or "")),
    )


def collect_customer_status_rows(result: dict[str, Any]) -> list[dict[str, str]]:
    """One table row per (CVE × image) — mirrors collectCustomerStatusRows."""
    out: list[dict[str, str]] = []
    for row in _sorted_rows(cve_rows_from_result(result)):
        severity = _severity_for_comment(row)

        def push(image_label: str, sec_keys: list[str], basename: str = "") -> None:
            fix, tag = _comment_plat_raw_for_keys(row, sec_keys)
            invalid = plat_issue_status_invalid_for_keys(row, sec_keys)
            pending = _pending_vendor_fix(row, sec_keys)
            if invalid:
                expected = "Package not found" if (basename and _package_not_found(row, basename)) else "N/A"
            elif pending:
                expected = "Pending Vendor Fix"
            else:
                expected = _expected_release_for_comment(fix, tag)
            out.append({
                "cve": str(row.get("cve_id") or ""),
                "severity": severity,
                "image": image_label,
                "package_name": _package_name(row, basename) if basename else "—",
                "expected_release": expected,
                "fix_version": "N/A" if (invalid or pending) else _release_version(fix, tag),
            })

        basenames = image_basenames_for_cve_row(row)
        if basenames:
            for bn in basenames:
                push(_image_label(row, bn), plat_sec_keys_for_image(row, bn), bn)
            orphan = _plat_orphan_sec_keys(row)
            if orphan:
                push("Unmapped Security PLAT", orphan)
            continue

        sec_keys = plat_security_keys(row)
        imgs = [i for i in (row.get("affected_images") or []) if i.get("image") and i["image"] != "NA"]
        if imgs:
            for img in imgs:
                bn = _image_path_basename(str(img.get("image") or ""))
                push(_image_label(row, bn) if bn else "—", sec_keys, bn)
        else:
            push("—", sec_keys)
    return out


def _pending_vendor_fix(row: dict[str, Any], sec_keys: list[str]) -> bool:
    sync: dict[str, Any] = row.get("plat_security_field_sync") or {}
    for key in sec_keys:
        entry = sync.get(key)
        if isinstance(entry, dict) and plat_issue_status_is_pending_vendor_fix(entry.get("issue_status")):
            return True
    return False


def format_customer_status_table(table_rows: list[dict[str, str]]) -> list[str]:
    """Plain-text pipe table — mirrors formatCustomerStatusTable."""
    if not table_rows:
        return []
    widths = [
        max(min_w, len(header), *(len(r.get(key, "")) for r in table_rows))
        for header, min_w, key in _COL_SPECS
    ]
    header_line = " | ".join(h.ljust(w) for (h, _, _), w in zip(_COL_SPECS, widths, strict=True))
    rule = "-+-".join("-" * w for w in widths)
    body = [
        " | ".join(r.get(key, "").ljust(w) for (_, _, key), w in zip(_COL_SPECS, widths, strict=True))
        for r in table_rows
    ]
    return [header_line, rule, *body]


def build_customer_status_comment(result: dict[str, Any], today: dt.date | None = None) -> str:
    """Full comment text — mirrors buildCustomerStatusComment (fixed default columns)."""
    lines = list(build_customer_status_comment_intro(today))
    table_rows = collect_customer_status_rows(result)
    if not table_rows:
        lines.append("No CVE rows to display.")
    else:
        lines.extend(format_customer_status_table(table_rows))
    return "\n".join(lines).rstrip()
