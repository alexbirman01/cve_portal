from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass
from typing import Any

import openpyxl
import pdfplumber


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Fallback regex for image:tag in free text (PDF / description).
# Image must contain at least one letter; allows optional space after colon.
_IMAGE_RE = re.compile(
    r"(?P<image>[a-zA-Z0-9._/-]*[a-zA-Z][a-zA-Z0-9._/-]*): ?(?P<tag>[a-zA-Z0-9._-]{1,128})"
)

# Column keyword aliases — order matters: first match wins.
_COL_ALIASES: dict[str, list[str]] = {
    "vuln":    ["vulnerability", "cve id", "cve"],
    "image":   ["image repository", "image repo", "image name", "container", "repository", "repo"],
    "tag":     ["tag", "version", "image tag"],
    "package": ["packages", "package name", "package"],
    "pkg_ver": ["package version", "pkg version", "version"],
    "fix":     ["fix status", "fix", "remediation", "fixed version"],
}

_FIX_VER_RE = re.compile(r"fixed in\s+([^\s,;]+)", re.IGNORECASE)
# Version-like string: starts with a digit, contains at least one dot or dash
_PLAIN_VER_RE = re.compile(r"^\d[\w.\-+~^]*$")


# ─── dataclasses ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ExtractedCve:
    cve_id: str
    source: str


@dataclass(frozen=True)
class ExtractedImage:
    image: str
    tag: str
    source: str


@dataclass(frozen=True)
class ExtractedPackage:
    cve_id: str
    package_name: str
    package_version: str | None   # installed/vulnerable version
    fixed_version: str | None     # from "Fix Status" column
    source: str


@dataclass(frozen=True)
class CveImageFact:
    """A directly-linked (CVE_ID, image, tag) fact extracted from a structured row."""
    cve_id: str
    image: str
    tag: str
    source: str


@dataclass(frozen=True)
class ParsedAttachment:
    attachment_id: str
    filename: str
    mime_type: str | None
    status: str  # ok | unparsed | needs_ocr | error
    text_preview: str | None
    cves: list[ExtractedCve]
    images: list[ExtractedImage]          # legacy: free-text image extraction
    packages: list[ExtractedPackage]
    cve_image_facts: list[CveImageFact]   # structured: (CVE, image, tag) per row


# ─── helpers ─────────────────────────────────────────────────────────────────

def _find_col(header: tuple, alias_key: str) -> int | None:
    """Return the first column index whose header matches any alias for the given key."""
    keywords = _COL_ALIASES.get(alias_key, [])
    for kw in keywords:
        for i, h in enumerate(header):
            if h and kw in str(h).lower():
                return i
    return None


def _parse_fix_version(raw: str | None) -> str | None:
    if not raw:
        return None
    s = str(raw).strip()
    # Pattern 1: "Fixed in 3.8.13"
    m = _FIX_VER_RE.search(s)
    if m:
        return m.group(1)
    # Pattern 2: bare version string like "3.8.13" or "1.2.3-4"
    if _PLAIN_VER_RE.match(s):
        return s
    return None


# ─── public extraction helpers ───────────────────────────────────────────────

def extract_cves(text: str, source: str) -> list[ExtractedCve]:
    return [ExtractedCve(cve_id=m.group(0).upper(), source=source) for m in _CVE_RE.finditer(text or "")]


def cve_ids_from_attachment_facts(parsed_attachments: list[dict]) -> list[str]:
    """Return sorted unique CVE IDs from structured Excel/Aqua JSON facts only.

    Description and PDF free-text CVE mentions must not create findings rows.
    ``parsed_attachments`` entries are dicts with a ``cve_image_facts`` list
    (as produced by the worker after ``parse_attachment_bytes``).
    """
    return sorted(
        {
            f["cve_id"]
            for p in parsed_attachments
            for f in (p.get("cve_image_facts") or [])
            if isinstance(f, dict) and f.get("cve_id")
        }
    )


def extract_images(text: str, source: str) -> list[ExtractedImage]:
    out: list[ExtractedImage] = []
    for m in _IMAGE_RE.finditer(text or ""):
        out.append(ExtractedImage(image=m.group("image"), tag=m.group("tag"), source=source))
    return out


# ─── PDF parser ──────────────────────────────────────────────────────────────

def parse_pdf_bytes(data: bytes, source: str, attachment_id: str, filename: str, mime_type: str | None) -> ParsedAttachment:
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            texts: list[str] = []
            for page in pdf.pages:
                t = page.extract_text() or ""
                if t:
                    texts.append(t)
            full_text = "\n\n".join(texts).strip()
    except Exception as e:
        return ParsedAttachment(
            attachment_id=attachment_id, filename=filename, mime_type=mime_type,
            status="error", text_preview=str(e)[:1000],
            cves=[], images=[], packages=[], cve_image_facts=[],
        )

    if not full_text:
        return ParsedAttachment(
            attachment_id=attachment_id, filename=filename, mime_type=mime_type,
            status="needs_ocr", text_preview=None,
            cves=[], images=[], packages=[], cve_image_facts=[],
        )

    cves   = extract_cves(full_text, source)
    images = extract_images(full_text, source)
    return ParsedAttachment(
        attachment_id=attachment_id, filename=filename, mime_type=mime_type,
        status="ok", text_preview=full_text[:2000],
        cves=cves, images=images, packages=[], cve_image_facts=[],
    )


# ─── Excel parser ─────────────────────────────────────────────────────────────

def parse_excel_bytes(data: bytes, source: str, attachment_id: str, filename: str, mime_type: str | None) -> ParsedAttachment:
    try:
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)

        # Collect structured facts; use a set to dedup (CVE, image, tag) across sheets.
        seen_facts: set[tuple[str, str, str]] = set()
        cve_image_facts: list[CveImageFact] = []
        packages: list[ExtractedPackage] = []
        seen_pkgs: set[tuple[str, str]] = set()  # (cve_id, package_name)
        texts: list[str] = []

        for sheet in wb.worksheets:
            rows = list(sheet.iter_rows(values_only=True))
            if len(rows) < 2:
                continue

            header = rows[0]

            # Detect column positions using alias table.
            vuln_col = _find_col(header, "vuln")
            img_col  = _find_col(header, "image")
            tag_col  = _find_col(header, "tag")
            pkg_col  = _find_col(header, "package")
            ver_col  = _find_col(header, "pkg_ver")
            fix_col  = _find_col(header, "fix")

            for row in rows:
                # Always collect raw text for fallback CVE regex extraction.
                row_vals = [str(v) for v in row if v is not None]
                if row_vals:
                    texts.append(" | ".join(row_vals))

                if row is rows[0]:
                    continue  # skip header row for structured extraction

                # Need at minimum a CVE column to do structured extraction.
                if vuln_col is None:
                    continue

                cve_raw = str(row[vuln_col]).strip() if row[vuln_col] else ""
                if not _CVE_RE.match(cve_raw):
                    continue
                cve_id = cve_raw.upper()

                # ── (CVE, image, tag) fact ──
                if img_col is not None and row[img_col]:
                    img_name = str(row[img_col]).strip()
                    img_tag  = str(row[tag_col]).strip() if tag_col is not None and row[tag_col] else ""
                    key = (cve_id, img_name, img_tag)
                    if img_name and key not in seen_facts:
                        seen_facts.add(key)
                        cve_image_facts.append(CveImageFact(
                            cve_id=cve_id,
                            image=img_name,
                            tag=img_tag,
                            source=source,
                        ))

                # ── package fact ──
                if pkg_col is not None and row[pkg_col]:
                    pkg_name = str(row[pkg_col]).strip()
                    pkg_key  = (cve_id, pkg_name)
                    if pkg_key not in seen_pkgs:
                        seen_pkgs.add(pkg_key)
                        pkg_ver = str(row[ver_col]).strip() if ver_col is not None and row[ver_col] else None
                        fix_raw = str(row[fix_col]).strip() if fix_col is not None and row[fix_col] else None
                        packages.append(ExtractedPackage(
                            cve_id=cve_id,
                            package_name=pkg_name,
                            package_version=pkg_ver or None,
                            fixed_version=_parse_fix_version(fix_raw),
                            source=source,
                        ))

        full_text = "\n".join(texts)

        # Always extract CVEs from raw text (catches any format not in known columns).
        cves = extract_cves(full_text, source)

        # Images: use free-text regex only as fallback when structured extraction found nothing.
        images = [] if cve_image_facts else extract_images(full_text, source)

    except Exception as e:
        return ParsedAttachment(
            attachment_id=attachment_id, filename=filename, mime_type=mime_type,
            status="error", text_preview=str(e)[:1000],
            cves=[], images=[], packages=[], cve_image_facts=[],
        )

    return ParsedAttachment(
        attachment_id=attachment_id, filename=filename, mime_type=mime_type,
        status="ok", text_preview=full_text[:2000],
        cves=cves, images=images, packages=packages, cve_image_facts=cve_image_facts,
    )


# ─── Aqua Security JSON parser ────────────────────────────────────────────────

# ECR transactional tags: {version}_{Service}_{suffix}
# suffix is usually DDMonYYYY (e.g. 15Jun2026) but can be non-calendar
# (e.g. Junhotfix2026). Service may contain underscores (pip_operator).
_AQUA_TAG_SERVICE_RE = re.compile(r"^([\d.]+)_(.+)_(.+)$")


def _aqua_image_basename(image_name: str) -> tuple[str, str]:
    """Return (service_token, tag) extracted from a full Aqua image_name field.

    image_name format:
      registry/repo:version_ServiceName_suffix  (ECR transactional repo)
      registry/repo:tag                         (standard naming)

    The service token is the segment between the version and trailing suffix when
    the tag follows the Aqua transactional pattern; otherwise it is the repo path.
    Underscores in the service token are normalized to hyphens for catalog matching
    (e.g. pip_operator → pip-operator).
    """
    s = image_name.strip()
    # Strip registry prefix (first component containing "." or port ":")
    parts = s.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or (parts[0].count(":") == 1 and parts[0].split(":")[1].isdigit())):
        s = parts[1]
    # Split tag
    if ":" in s:
        repo, tag = s.rsplit(":", 1)
    else:
        repo, tag = s, ""
    # Try to extract a service identifier from {version}_{Service}_{suffix}
    m = _AQUA_TAG_SERVICE_RE.match(tag)
    if m:
        service = m.group(2).lower().replace("_", "-")
    else:
        service = repo.strip().lower()
    return service, tag.strip()


def parse_aqua_json_bytes(
    data: bytes,
    source: str,
    attachment_id: str,
    filename: str,
    mime_type: str | None,
    alias_map: dict[str, str] | None = None,
) -> ParsedAttachment:
    """Parse an Aqua Security scan report JSON attachment.

    Supports the format exported by Aqua Cloud (array of scan results with
    ``image_name`` and ``results.resources[].vulnerabilities[]``).
    ``alias_map`` resolves vendor-specific service tokens to canonical image basenames.
    """
    try:
        raw = json.loads(data.decode("utf-8", errors="replace"))
    except Exception as exc:
        return ParsedAttachment(
            attachment_id=attachment_id, filename=filename, mime_type=mime_type,
            status="error", text_preview=str(exc)[:500],
            cves=[], images=[], packages=[], cve_image_facts=[],
        )

    # Validate Aqua shape: list of scan entries with image_name + results.resources
    if not isinstance(raw, list) or not raw:
        return ParsedAttachment(
            attachment_id=attachment_id, filename=filename, mime_type=mime_type,
            status="unparsed", text_preview=None,
            cves=[], images=[], packages=[], cve_image_facts=[],
        )
    first = raw[0] if isinstance(raw[0], dict) else {}
    if "image_name" not in first or "results" not in first:
        return ParsedAttachment(
            attachment_id=attachment_id, filename=filename, mime_type=mime_type,
            status="unparsed", text_preview=None,
            cves=[], images=[], packages=[], cve_image_facts=[],
        )

    seen_facts: set[tuple[str, str, str]] = set()
    cve_image_facts: list[CveImageFact] = []
    packages: list[ExtractedPackage] = []
    seen_pkgs: set[tuple[str, str]] = set()
    all_cve_ids: list[str] = []

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        image_name = str(entry.get("image_name") or "")
        service_token, tag = _aqua_image_basename(image_name)
        # Resolve alias → canonical name; fall back to the token itself
        canonical = (alias_map or {}).get(service_token, service_token)

        resources = (entry.get("results") or {}).get("resources") or []
        for res in resources:
            if not isinstance(res, dict):
                continue
            pkg = res.get("resource") or {}
            pkg_name = str(pkg.get("name") or "").strip()
            pkg_version = str(pkg.get("version") or "").strip() or None

            for vuln in (res.get("vulnerabilities") or []):
                if not isinstance(vuln, dict):
                    continue
                cve_raw = str(vuln.get("name") or "").strip()
                if not _CVE_RE.match(cve_raw):
                    continue
                cve_id = cve_raw.upper()
                all_cve_ids.append(cve_id)

                key = (cve_id, canonical, tag)
                if key not in seen_facts:
                    seen_facts.add(key)
                    cve_image_facts.append(CveImageFact(
                        cve_id=cve_id,
                        image=canonical,
                        tag=tag,
                        source=source,
                    ))

                if pkg_name:
                    pkg_key = (cve_id, pkg_name)
                    if pkg_key not in seen_pkgs:
                        seen_pkgs.add(pkg_key)
                        packages.append(ExtractedPackage(
                            cve_id=cve_id,
                            package_name=pkg_name,
                            package_version=pkg_version,
                            fixed_version=None,
                            source=source,
                        ))

    cves = [ExtractedCve(cve_id=c, source=source) for c in dict.fromkeys(all_cve_ids)]
    return ParsedAttachment(
        attachment_id=attachment_id, filename=filename, mime_type=mime_type,
        status="ok", text_preview=None,
        cves=cves, images=[], packages=packages, cve_image_facts=cve_image_facts,
    )


# ─── dispatcher ──────────────────────────────────────────────────────────────

def parse_attachment_bytes(
    *,
    attachment_id: str,
    filename: str,
    mime_type: str | None,
    data: bytes,
    alias_map: dict[str, str] | None = None,
) -> ParsedAttachment:
    source = f"attachment:{attachment_id}:{filename}"
    lower  = filename.lower()

    if lower.endswith((".xlsx", ".xlsm", ".xltx", ".xltm")) or mime_type in (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
    ):
        return parse_excel_bytes(data, source, attachment_id, filename, mime_type)

    if lower.endswith(".pdf") or mime_type == "application/pdf":
        return parse_pdf_bytes(data, source, attachment_id, filename, mime_type)

    if lower.endswith(".json"):
        return parse_aqua_json_bytes(data, source, attachment_id, filename, mime_type, alias_map=alias_map)

    return ParsedAttachment(
        attachment_id=attachment_id, filename=filename, mime_type=mime_type,
        status="unparsed", text_preview=None,
        cves=[], images=[], packages=[], cve_image_facts=[],
    )


# ─── ADF / Jira description helpers ──────────────────────────────────────────

def _adf_node_to_text(node: Any) -> str:
    """Recursively convert an Atlassian Document Format node to plain text."""
    if not isinstance(node, dict):
        return ""
    ntype = node.get("type", "")
    if ntype == "text":
        return node.get("text", "")
    if ntype == "hardBreak":
        return "\n"
    children = node.get("content") or []
    if ntype == "tableRow":
        cells = [_adf_node_to_text(c).rstrip("\n") for c in children]
        return " | ".join(cells) + "\n"
    if ntype in ("tableHeader", "tableCell"):
        return "".join(_adf_node_to_text(c) for c in children)
    if ntype == "table":
        return "".join(_adf_node_to_text(r) for r in children)
    inner = "".join(_adf_node_to_text(c) for c in children)
    if ntype in ("paragraph", "heading", "listItem"):
        return inner + "\n"
    if ntype in ("bulletList", "orderedList"):
        return inner
    return inner


def normalize_description(description_raw: Any) -> str:
    """Return a plain-text representation suitable for CVE extraction and display."""
    if description_raw is None:
        return ""
    if isinstance(description_raw, dict) and description_raw.get("type") == "doc":
        return _adf_node_to_text(description_raw).strip()
    return str(description_raw)
