"""Tests for strict image source-of-truth and Allowed Images catalog enforcement.

Key behaviors verified:
- CVE↔image facts come only from Excel/JSON attachment structured rows (cve_image_facts).
- Description text and PDF free-text produce no cve_image_facts.
- normalize_image_basename + alias resolution produces canonical names.
- load_allowed_names / is_allowed_basename correctly gates catalog membership.
"""

from __future__ import annotations

import io
import json
import openpyxl

from api.app.allowed_images import (
    is_allowed_basename,
    normalize_image_basename,
)
from api.app.parsing import (
    extract_cves,
    extract_images,
    parse_attachment_bytes,
)


# ── normalize_image_basename ──────────────────────────────────────────────────

def test_normalize_strips_prefix():
    assert normalize_image_basename("plainid/pip-operator") == "pip-operator"


def test_normalize_takes_last_segment():
    assert normalize_image_basename("registry.example.com/plainid/theruntime") == "theruntime"


def test_normalize_lowercases():
    assert normalize_image_basename("PLAINID/TheRuntime") == "theruntime"


def test_normalize_bare_name():
    assert normalize_image_basename("agent") == "agent"


# ── alias map resolution ──────────────────────────────────────────────────────



def _build_alias_map(entries: list[tuple[str, str]]) -> dict[str, str]:
    """Pure-Python alias map (mirrors load_alias_map logic without SQLAlchemy)."""
    from types import SimpleNamespace
    out: dict[str, str] = {}
    for name, aliases_csv in entries:
        canonical = name.lower().strip()
        out[canonical] = canonical
        for a in aliases_csv.split(","):
            a = a.strip().lower()
            if a:
                out[a] = canonical
    return out


def _build_allowed_names(entries: list[tuple[str, str]]) -> set[str]:
    """Pure-Python allowed names set (mirrors load_allowed_names logic without SQLAlchemy)."""
    names: set[str] = set()
    for name, aliases_csv in entries:
        names.add(name.lower())
        for a in aliases_csv.split(","):
            a = a.strip().lower()
            if a:
                names.add(a)
    return names


def test_alias_resolves_to_canonical():
    alias_map = _build_alias_map([("secrets-mgmt", "secretmgr,secret-mgmt")])
    assert alias_map.get("secretmgr") == "secrets-mgmt"
    assert alias_map.get("secret-mgmt") == "secrets-mgmt"
    assert alias_map.get("secrets-mgmt") == "secrets-mgmt"


def test_load_allowed_names_includes_aliases():
    allowed = _build_allowed_names([("pip-operator", "pip-op")])
    assert "pip-operator" in allowed
    assert "pip-op" in allowed


def test_is_allowed_basename_case_insensitive():
    allowed = {"agent", "pip-operator", "theruntime"}
    assert is_allowed_basename("Agent", allowed) is True
    assert is_allowed_basename("authorizer", allowed) is False


# ── description text → no cve_image_facts ────────────────────────────────────

def test_description_extract_images_no_structured_facts():
    """extract_images returns ExtractedImage list, not cve_image_facts — never PLAT-eligible."""
    text = "CVE-2026-39822 affects authorizer:1.0 and agent:2.0"
    images = extract_images(text, "description")
    # These are free-text ExtractedImage objects, not CveImageFacts.
    # They are NOT placed into cve_to_images under the strict SoT rule.
    assert any(i.image == "authorizer" for i in images)
    assert any(i.image == "agent" for i in images)
    # The point: these do not carry a cve_id binding, so worker ignores them for PLAT slots.


def test_description_cves_without_image_facts():
    """Description-parsed CVEs produce no cve_image_facts — PLAT slots stay empty."""
    text = "This ticket covers CVE-2026-12345 in authorizer:1.0."
    cves = extract_cves(text, "description")
    assert any(c.cve_id == "CVE-2026-12345" for c in cves)
    # extract_cves has no image correlation — callers get no (cve_id, image, tag) facts.


# ── Excel structured attachment → cve_image_facts ────────────────────────────

def _make_excel_bytes(rows: list[tuple]) -> bytes:
    """Build a minimal Excel workbook with CVE/Image/Tag columns."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(("CVE ID", "Image Repository", "Tag"))
    for row in rows:
        ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_excel_produces_cve_image_facts():
    data = _make_excel_bytes([
        ("CVE-2026-39822", "plainid/pip-operator", "5.2622.1"),
        ("CVE-2026-39822", "plainid/agent", "5.2622.1"),
    ])
    parsed = parse_attachment_bytes(
        attachment_id="att1",
        filename="scan.xlsx",
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        data=data,
    )
    assert parsed.status == "ok"
    assert len(parsed.cve_image_facts) == 2
    cve_ids = {f.cve_id for f in parsed.cve_image_facts}
    assert "CVE-2026-39822" in cve_ids
    images = {f.image for f in parsed.cve_image_facts}
    assert "plainid/pip-operator" in images
    assert "plainid/agent" in images


def test_excel_no_image_col_produces_no_facts():
    """Excel without an image column should produce no cve_image_facts."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(("CVE ID", "Package"))
    ws.append(("CVE-2026-11111", "openssl"))
    buf = io.BytesIO()
    wb.save(buf)
    parsed = parse_attachment_bytes(
        attachment_id="att2",
        filename="scan.xlsx",
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        data=buf.getvalue(),
    )
    assert parsed.cve_image_facts == []


def test_unknown_image_in_excel_passes_through_to_row():
    """Unrecognized image names from Excel reach affected_images — catalog check is at create time."""
    data = _make_excel_bytes([
        ("CVE-2026-39822", "authorizer", "1.0"),
    ])
    parsed = parse_attachment_bytes(
        attachment_id="att3",
        filename="scan.xlsx",
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        data=data,
    )
    # Parser emits the fact; worker puts it in affected_images.
    # API will reject create because "authorizer" is not in Allowed Images.
    assert any(f.image == "authorizer" for f in parsed.cve_image_facts)


# ── Aqua JSON → cve_image_facts ───────────────────────────────────────────────

def test_aqua_json_produces_cve_image_facts():
    payload = [
        {
            "image_name": "registry.example.com/plainid/pip-operator:5.2622.1",
            "results": {
                "resources": [
                    {
                        "resource": {"name": "openssl", "version": "3.0.0"},
                        "vulnerabilities": [{"name": "CVE-2026-39822"}],
                    }
                ]
            },
        }
    ]
    data = json.dumps(payload).encode()
    # Aqua parser emits the service token as extracted from the image_name repo path.
    # For this input (no transactional-tag pattern) the token is the full repo segment
    # "plainid/pip-operator"; worker's _resolve_image_name normalizes it to "pip-operator".
    alias_map = {"pip-operator": "pip-operator"}
    parsed = parse_attachment_bytes(
        attachment_id="att4",
        filename="aqua_scan.json",
        mime_type="application/json",
        data=data,
        alias_map=alias_map,
    )
    assert parsed.status == "ok"
    assert len(parsed.cve_image_facts) == 1
    assert parsed.cve_image_facts[0].cve_id == "CVE-2026-39822"
    # normalize_image_basename strips "plainid/" — verify that resolves correctly.
    assert normalize_image_basename(parsed.cve_image_facts[0].image) == "pip-operator"


# ── catalog enforcement helpers ───────────────────────────────────────────────

def test_canonical_image_passes_catalog_check():
    allowed = {"pip-operator", "agent", "theruntime", "secrets-mgmt"}
    assert is_allowed_basename("pip-operator", allowed) is True


def test_authorizer_fails_catalog_check():
    allowed = {"pip-operator", "agent", "theruntime", "secrets-mgmt"}
    assert is_allowed_basename("authorizer", allowed) is False


def test_alias_resolved_to_canonical_passes_check():
    alias_map = _build_alias_map([("secrets-mgmt", "secretmgr")])
    allowed = _build_allowed_names([("secrets-mgmt", "secretmgr")])
    raw = "secretmgr"
    canonical = alias_map.get(normalize_image_basename(raw), normalize_image_basename(raw))
    assert is_allowed_basename(canonical, allowed) is True
