"""Derive PLAT/CVE states from stored cve_rows JSON (aligned with ui/src/api.ts)."""

from __future__ import annotations

from typing import Any

from api.app.package_name import canonical_single_package_name


def _image_path_basename(image_path: str) -> str:
    s = image_path.replace("plainid/", "").replace("PLAINID/", "")
    parts = s.strip().split("/")
    return parts[-1].strip() if parts else ""


def image_basenames_for_cve_row(row: dict[str, Any]) -> list[str]:
    imgs = [i for i in (row.get("affected_images") or []) if i.get("image") and i["image"] != "NA"]
    if imgs:
        names = [_image_path_basename(str(i["image"])) for i in imgs]
    elif row.get("affected_image") and row["affected_image"] != "NA":
        names = [_image_path_basename(str(row["affected_image"]))]
    else:
        names = []
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if not n:
            continue
        k = n.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(n)
    return out


def plat_security_keys(row: dict[str, Any]) -> list[str]:
    pk = row.get("plat_security_keys")
    if pk:
        return list(pk)
    tickets = row.get("plat_tickets") or []
    out = [t["key"] for t in tickets if t.get("issue_type") == "Security Vulnerability"]
    if out:
        return out
    pt = row.get("plat_ticket")
    return [str(pt)] if pt else []


def image_path_for_basename(row: dict[str, Any], image_basename: str) -> str | None:
    fold = image_basename.lower()
    imgs = [i for i in (row.get("affected_images") or []) if i.get("image") and i["image"] != "NA"]
    for i in imgs:
        if _image_path_basename(str(i["image"])).lower() == fold:
            return str(i["image"])
    ai = row.get("affected_image")
    if ai and ai != "NA" and _image_path_basename(str(ai)).lower() == fold:
        return str(ai)
    return None


def package_entry_for_image(row: dict[str, Any], image_basename: str) -> dict[str, Any]:
    """Per-image package/Aqua slice — mirrors packageEntryForImage in api.ts."""
    pbi: dict[str, Any] = row.get("package_by_image") or {}
    fold = image_basename.lower()
    if image_basename in pbi:
        entry = pbi[image_basename]
        return entry if isinstance(entry, dict) else {}
    for k, v in pbi.items():
        if str(k).lower() == fold and isinstance(v, dict):
            return v
    return {}


def plat_jira_package_name_for_row(row: dict[str, Any], image_basename: str | None = None) -> str:
    """
    Package Name for PLAT Jira (create + rewrite on sync).
    Go CVEs always use stdlib; confirmed Aqua name wins when present.
    """
    from api.app.aqua_packages import GO_AQUA_RESOURCE, is_nvd_go_packages

    nvd_pkgs = row.get("all_packages") or []
    is_go = is_nvd_go_packages(nvd_pkgs if isinstance(nvd_pkgs, list) else [])

    if image_basename:
        entry = package_entry_for_image(row, image_basename)
        apn = canonical_single_package_name(entry.get("aqua_package_name"))
        if entry.get("aqua_pkg_found") and apn:
            return apn
        if is_go:
            return GO_AQUA_RESOURCE
        res = canonical_single_package_name(entry.get("affected_resource"))
        if res:
            return res

    apn = canonical_single_package_name(row.get("aqua_package_name"))
    if row.get("aqua_pkg_found") and apn:
        return apn
    if is_go:
        return GO_AQUA_RESOURCE

    res = canonical_single_package_name(row.get("affected_resource"))
    if res:
        return res
    for p in nvd_pkgs:
        if isinstance(p, dict):
            product = canonical_single_package_name(p.get("product"))
            if product:
                return product
    return str(row.get("cve_id") or "").strip()


def plat_package_name_for_row(row: dict[str, Any], image_basename: str | None = None) -> str:
    """Best-effort package name for PLAT Package Name — mirrors platPackageNameForRow in api.ts."""
    return plat_jira_package_name_for_row(row, image_basename)


def plat_sec_keys_scoped_to_run(row: dict[str, Any]) -> set[str]:
    """
    Security Vuln PLAT keys for this PLATFORM run only (CVE row × affected images).

    Excludes other PLAT tickets in Jira that share the same CVE id but belong to
    images not on this ticket (the global plat_security_keys list).
    """
    out: set[str] = set()
    basenames = image_basenames_for_cve_row(row)
    per_img: dict[str, list[str]] = row.get("plat_security_for_images") or {}

    if per_img and basenames:
        for bn in basenames:
            for pk in plat_sec_keys_for_image(row, bn):
                k = str(pk).strip().upper()
                if k:
                    out.add(k)
        return out

    keys = plat_security_keys(row)
    if len(basenames) == 1 and len(keys) == 1:
        out.add(keys[0].strip().upper())
    return out


def iter_plat_security_package_targets(row: dict[str, Any]) -> list[tuple[str | None, str]]:
    """(image_basename, plat_key) pairs for updating Package Name on Security Vuln tickets."""
    out: list[tuple[str | None, str]] = []
    basenames = image_basenames_for_cve_row(row)
    for bn in basenames:
        for pk in plat_sec_keys_for_image(row, bn):
            k = str(pk).strip().upper()
            if not k:
                continue
            if any(existing[1] == k for existing in out):
                continue
            out.append((bn, k))
    if not out:
        keys = list(plat_sec_keys_scoped_to_run(row))
        if len(basenames) == 1 and len(keys) == 1:
            out.append((basenames[0], keys[0]))
    return out


def _plat_sync_field_usable(val: object) -> str:
    s = str(val or "").strip()
    if not s or s.casefold() == "none":
        return ""
    return s


def plat_sync_entry_for_row_primary(row: dict[str, Any]) -> dict[str, Any] | None:
    """Best PLAT sync entry for row-level vendor fields (primary image / first linked key)."""
    sync_map: dict[str, Any] = row.get("plat_security_field_sync") or {}
    if not sync_map:
        return None
    for bn in image_basenames_for_cve_row(row):
        for pk in plat_sec_keys_for_image(row, bn):
            entry = sync_map.get(str(pk).strip().upper())
            if isinstance(entry, dict):
                return entry
    for pk in plat_security_keys(row):
        entry = sync_map.get(str(pk).strip().upper())
        if isinstance(entry, dict):
            return entry
    first = next(iter(sync_map.values()), None)
    return first if isinstance(first, dict) else None


def apply_plat_vendor_fields_from_sync(row: dict[str, Any]) -> None:
    """Overwrite row affected_version / fixed_version from Jira when PLAT sync has values."""
    entry = plat_sync_entry_for_row_primary(row)
    if not entry:
        return
    pv = _plat_sync_field_usable(entry.get("package_vuln_version"))
    if pv:
        row["affected_version"] = pv
    vf = _plat_sync_field_usable(entry.get("vendor_fix_version"))
    if vf:
        row["fixed_version"] = vf


def plat_sec_keys_for_image(row: dict[str, Any], image_basename: str) -> list[str]:
    m = row.get("plat_security_for_images") or {}
    if m and len(m) > 0:
        if m.get(image_basename):
            return list(m[image_basename])
        fold = image_basename.lower()
        for k, v in m.items():
            if str(k).lower() == fold and v:
                return list(v)
    imgs = image_basenames_for_cve_row(row)
    if len(imgs) == 1 and imgs[0].lower() == image_basename.lower():
        all_sec = plat_security_keys(row)
        if len(all_sec) == 1:
            return all_sec
    return []


def plat_missing_cve_create_slots_for_row(row: dict[str, Any]) -> list[tuple[str, str]]:
    """(cve_id, image_basename) pairs that would show 'Create CVE' in the UI."""
    ver = str(row.get("affected_version") or "").strip()
    if not ver:
        return []
    out: list[tuple[str, str]] = []
    cve_id = str(row.get("cve_id") or "")
    for bn in image_basenames_for_cve_row(row):
        if not plat_sec_keys_for_image(row, bn):
            out.append((cve_id, bn))
    return out


def plat_ticket_keys_for_row(row: dict[str, Any]) -> list[str]:
    """All Security Vulnerability PLAT keys linked to this CVE row (explicit, per-image)."""
    seen: set[str] = set()
    out: list[str] = []

    def add(raw: object) -> None:
        if raw is None:
            return
        s = str(raw).strip()
        if not s:
            return
        low = s.lower()
        if low in seen:
            return
        seen.add(low)
        out.append(s)

    for k in row.get("plat_security_keys") or []:
        add(k)
    for t in row.get("plat_tickets") or []:
        add((t or {}).get("key"))
    add(row.get("plat_ticket"))
    for _img, keys in (row.get("plat_security_for_images") or {}).items():
        for k in keys or []:
            add(k)
    return out


def plat_keys_aggregate_from_rows(rows: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for k in plat_ticket_keys_for_row(row):
            low = k.lower()
            if low in seen:
                continue
            seen.add(low)
            out.append(k)
    out.sort(key=lambda x: x.lower())
    return out


def derive_cve_state(row: dict[str, Any], run_status: str) -> str:
    """Single CV row state for dashboard badges (run must be logically 'done' for CVE semantics)."""
    if run_status.startswith("failed"):
        return "pipeline_failed"
    if run_status != "done":
        return "pipeline_running"

    nvd = row.get("nvd_state")
    if nvd == "error":
        return "nvd_error"

    basenames = image_basenames_for_cve_row(row)
    if not basenames:
        return "no_image"

    missing = plat_missing_cve_create_slots_for_row(row)
    if missing:
        return "needs_plat_cve"

    ver = str(row.get("affected_version") or "").strip()
    if not ver:
        return "needs_version"

    return "plat_complete"


def cve_rows_from_result(result: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not result:
        return []
    rows = result.get("cve_rows")
    return list(rows) if isinstance(rows, list) else []


# ── Remediation status helpers (mirrors ui/src/api.ts PLAT fix/tag/date logic) ─────────────

import re as _re
from datetime import date as _date


def _normalize_plat_sync_field_value(raw: str | None) -> str:
    s = (raw or "").strip()
    if not s or s.lower() == "none":
        return ""
    return s


def plat_issue_status_is_invalid(status: str | None) -> bool:
    """True when PLAT Security workflow status is Invalid (case-insensitive)."""
    return (status or "").strip().casefold() == "invalid"


def plat_issue_status_is_pending_vendor_fix(status: str | None) -> bool:
    """True when PLAT Security workflow status is Pending Vendor Fix (case-insensitive)."""
    return (status or "").strip().casefold() == "pending vendor fix"


def plat_issue_status_invalid_for_keys(row: dict[str, Any], sec_keys: list[str]) -> bool:
    """Any scoped Security PLAT key on this row has Invalid workflow status."""
    sync_map: dict[str, Any] = row.get("plat_security_field_sync") or {}
    for k in sec_keys:
        pk = k.strip().upper()
        if not pk:
            continue
        entry = sync_map.get(pk) or {}
        if plat_issue_status_is_invalid(str(entry.get("issue_status") or "")):
            return True
    return False


def _translate_fix_version_to_release_date(fix_version: str) -> str | None:
    """Return calendar date string for the first week-code found (e.g. '5.2627.x' → 'June 29, 2026')."""
    if not fix_version:
        return None
    pattern = _re.compile(r"\b\d\.(\d{2})(\d{2})\.[xX\d]+\b")
    months = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
    ]
    dates: list[str] = []
    seen: set[str] = set()
    for m in pattern.finditer(fix_version):
        yy, ww = int(m.group(1)), int(m.group(2))
        if ww < 1 or ww > 53:
            continue
        year = 2000 + yy
        # ISO Week 1 is the week containing Jan 4; find its Monday.
        jan4 = _date(year, 1, 4)
        dow = jan4.isoweekday()  # Monday=1
        week1_monday = _date.fromordinal(jan4.toordinal() - dow + 1)
        monday = _date.fromordinal(week1_monday.toordinal() + (ww - 1) * 7)
        formatted = f"{months[monday.month - 1]} {monday.day}, {monday.year}"
        if formatted not in seen:
            seen.add(formatted)
            dates.append(formatted)
    return dates[0] if dates else None


def _plain_id_expected_release_date(fix: str, tag: str) -> str:
    """'In progress' when no week-code can be resolved — mirrors plainIdExpectedReleaseDate in api.ts."""
    fix_in = _normalize_plat_sync_field_value(fix)
    tag_in = _normalize_plat_sync_field_value(tag)
    if fix_in:
        from_fix = _translate_fix_version_to_release_date(fix_in)
        if from_fix:
            return from_fix
    if tag_in:
        from_tag = _translate_fix_version_to_release_date(tag_in)
        if from_tag:
            return from_tag
    if fix_in:
        return fix_in
    return "In progress"


def _plat_orphan_sec_keys(row: dict[str, Any]) -> list[str]:
    """Security keys not covered by any known image mapping."""
    per_img: dict[str, list[str]] = row.get("plat_security_for_images") or {}
    if not per_img:
        return []
    all_mapped: set[str] = set()
    for keys in per_img.values():
        all_mapped.update(k.upper() for k in (keys or []))
    all_sec = [k.upper() for k in plat_security_keys(row)]
    return [k for k in all_sec if k not in all_mapped]


def _comment_plat_raw_for_keys(row: dict[str, Any], sec_keys: list[str]) -> tuple[str, str]:
    """(fix, tag) for these security keys — mirrors commentPlatRawForKeys in api.ts."""
    upper = sorted({k.strip().upper() for k in sec_keys if k.strip()})
    sync_map: dict[str, Any] = row.get("plat_security_field_sync") or {}
    has_map = bool(sync_map)

    if has_map and upper:
        if len(upper) == 1:
            entry = sync_map.get(upper[0]) or {}
            fix = _normalize_plat_sync_field_value(entry.get("fix_versions"))
            tag = _normalize_plat_sync_field_value(entry.get("tag_numbers"))
        else:
            fix = "\n".join(
                f"{k} · {_normalize_plat_sync_field_value((sync_map.get(k) or {}).get('fix_versions')) or '—'}"
                for k in upper
            )
            tag = "\n".join(
                f"{k} · {_normalize_plat_sync_field_value((sync_map.get(k) or {}).get('tag_numbers')) or '—'}"
                for k in upper
            )
        return fix, tag

    if not has_map and not sec_keys:
        lf = _normalize_plat_sync_field_value(row.get("plat_app_fix_versions"))
        lt = _normalize_plat_sync_field_value(row.get("plat_tag_numbers"))
        return lf, lt

    return "", ""


def collect_customer_status_slots(row: dict[str, Any]) -> list[dict[str, str]]:
    """
    Return one slot dict per (CVE × image) — mirrors collectCustomerStatusRows in api.ts.

    Each slot: {fix, tag, expected_release}
    """
    out: list[dict[str, str]] = []
    per_img: dict[str, list[str]] = row.get("plat_security_for_images") or {}
    basenames = image_basenames_for_cve_row(row)

    if basenames:
        for bn in basenames:
            sec_keys = plat_sec_keys_for_image(row, bn)
            fix, tag = _comment_plat_raw_for_keys(row, sec_keys)
            out.append({"fix": fix, "tag": tag, "expected_release": _plain_id_expected_release_date(fix, tag)})
        orphan = _plat_orphan_sec_keys(row)
        if orphan:
            fix, tag = _comment_plat_raw_for_keys(row, orphan)
            out.append({"fix": fix, "tag": tag, "expected_release": _plain_id_expected_release_date(fix, tag)})
        return out

    imgs = [i for i in (row.get("affected_images") or []) if i.get("image") and i["image"] != "NA"]
    legacy = ""
    if not imgs and row.get("affected_image") and row["affected_image"] != "NA":
        ai = str(row["affected_image"])
        at = str(row.get("affected_tag") or "").strip()
        legacy = f"{ai.replace('plainid/', '').replace('PLAINID/', '')}:{at}" if at else ai.replace("plainid/", "")

    sec_keys = plat_security_keys(row)
    if legacy or imgs:
        targets = [legacy] if legacy else imgs
        for _ in targets:
            fix, tag = _comment_plat_raw_for_keys(row, sec_keys)
            out.append({"fix": fix, "tag": tag, "expected_release": _plain_id_expected_release_date(fix, tag)})
    else:
        fix, tag = _comment_plat_raw_for_keys(row, sec_keys)
        out.append({"fix": fix, "tag": tag, "expected_release": _plain_id_expected_release_date(fix, tag)})

    return out


_REMEDIATION_STATUSES = (
    "error",
    "processing",
    "package_not_matched",
    "needs_plat",
    "initialized",
    "waiting_release_date",
    "waiting_tags",
    "done",
)


def derive_ticket_remediation_status(
    rows: list[dict[str, Any]],
    run_status: str,
    result: dict[str, Any] | None,
) -> str:
    """
    Ticket-level remediation status for the dashboard.

    Priority: error → processing → package_not_matched → needs_plat → initialized →
              waiting_release_date → waiting_tags → done
    """
    # Error: run failed, sync errors present, or any CVE has nvd_state=error
    if run_status.startswith("failed"):
        return "error"
    if result and result.get("_plat_sync_errors"):
        return "error"
    if any(r.get("nvd_state") == "error" for r in rows if isinstance(r, dict)):
        return "error"

    # Processing: pipeline not finished
    if run_status != "done":
        return "processing"

    # Package not matched: any image entry in package_by_image (or legacy aqua_pkg_by_image) failed
    def _any_image_not_matched(r: dict) -> bool:
        pbi = r.get("package_by_image") or {}
        if pbi:
            return any(
                e.get("aqua_checked") and e.get("aqua_pkg_found") is False
                for e in pbi.values()
                if isinstance(e, dict)
            )
        # Fallback to legacy map
        legacy = r.get("aqua_pkg_by_image") or {}
        if legacy:
            return any(
                e.get("aqua_checked") and e.get("found") is False
                for e in legacy.values()
                if isinstance(e, dict)
            )
        return r.get("aqua_pkg_found") is False

    if any(_any_image_not_matched(r) for r in rows if isinstance(r, dict)):
        return "package_not_matched"

    # Needs PLAT: any Security-Vuln slot missing
    for row in rows:
        if not isinstance(row, dict):
            continue
        if plat_missing_cve_create_slots_for_row(row):
            return "needs_plat"

    # Initialized: no plat_security_field_sync on any row
    has_any_sync = any(
        bool(r.get("plat_security_field_sync"))
        for r in rows
        if isinstance(r, dict)
    )
    if not has_any_sync:
        return "initialized"

    # Collect all slots across all rows
    all_slots: list[dict[str, str]] = []
    for row in rows:
        if isinstance(row, dict):
            all_slots.extend(collect_customer_status_slots(row))

    if not all_slots:
        return "initialized"

    # Waiting for release date: any slot has no resolved date
    if any(s["expected_release"] == "In progress" for s in all_slots):
        return "waiting_release_date"

    # Waiting for tags: at least one slot missing tag numbers
    if any(not _normalize_plat_sync_field_value(s["tag"]) for s in all_slots):
        return "waiting_tags"

    return "done"
