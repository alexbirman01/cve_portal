"""Derive PLAT/CVE states from stored cve_rows JSON (aligned with ui/src/api.ts)."""

from __future__ import annotations

from typing import Any


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
    """All PLAT-style issue keys linked to this CVE row (sec, bug, per-image)."""
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
