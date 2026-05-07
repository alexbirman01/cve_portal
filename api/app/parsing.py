from __future__ import annotations

import io
import re
from dataclasses import dataclass
from typing import Any

import openpyxl
import pdfplumber


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Matches Docker-style image:tag AND "name: version" (with optional space after colon).
# Image must contain at least one letter (filters out pure numeric patterns like 8:00).
# Tag/version may start with a digit (e.g. 5.2603.0).
_IMAGE_RE = re.compile(
    r"(?P<image>[a-zA-Z0-9._/-]*[a-zA-Z][a-zA-Z0-9._/-]*): ?(?P<tag>[a-zA-Z0-9._-]{1,128})"
)


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
    package_version: str | None   # installed/vulnerable version from spreadsheet
    fixed_version: str | None     # extracted from "Fix Status" column
    source: str


@dataclass(frozen=True)
class ParsedAttachment:
    attachment_id: str
    filename: str
    mime_type: str | None
    status: str  # ok | unparsed | needs_ocr | error
    text_preview: str | None
    cves: list[ExtractedCve]
    images: list[ExtractedImage]
    packages: list[ExtractedPackage]


def extract_cves(text: str, source: str) -> list[ExtractedCve]:
    return [ExtractedCve(cve_id=m.group(0).upper(), source=source) for m in _CVE_RE.finditer(text or "")]


def extract_images(text: str, source: str) -> list[ExtractedImage]:
    out: list[ExtractedImage] = []
    for m in _IMAGE_RE.finditer(text or ""):
        out.append(ExtractedImage(image=m.group("image"), tag=m.group("tag"), source=source))
    return out


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
            attachment_id=attachment_id,
            filename=filename,
            mime_type=mime_type,
            status="error",
            text_preview=str(e)[:1000],
            cves=[],
            images=[],
            packages=[],
        )

    if not full_text:
        return ParsedAttachment(
            attachment_id=attachment_id,
            filename=filename,
            mime_type=mime_type,
            status="needs_ocr",
            text_preview=None,
            cves=[],
            images=[],
            packages=[],
        )

    cves = extract_cves(full_text, source)
    images = extract_images(full_text, source)
    return ParsedAttachment(
        attachment_id=attachment_id,
        filename=filename,
        mime_type=mime_type,
        status="ok",
        text_preview=full_text[:2000],
        cves=cves,
        images=images,
        packages=[],
    )


_FIX_STATUS_RE = re.compile(r"fixed in\s+([^\s,;]+)", re.IGNORECASE)

def _parse_fix_status(fix_status: str | None) -> str | None:
    """Extract the first version string from 'Fix Status' values like 'fixed in 2.4.67-r0'."""
    if not fix_status:
        return None
    m = _FIX_STATUS_RE.search(str(fix_status))
    return m.group(1) if m else None


def _find_col(header: tuple, *keywords: str) -> int | None:
    """Return the index of the first header cell matching any keyword (case-insensitive)."""
    for i, h in enumerate(header):
        if h and any(kw in str(h).lower() for kw in keywords):
            return i
    return None


def parse_excel_bytes(data: bytes, source: str, attachment_id: str, filename: str, mime_type: str | None) -> ParsedAttachment:
    try:
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        texts: list[str] = []
        packages: list[ExtractedPackage] = []

        for sheet in wb.worksheets:
            rows = list(sheet.iter_rows(values_only=True))
            if not rows:
                continue

            # Detect known structured columns (Vulnerability/CVE scanner exports).
            header = rows[0]
            vuln_col   = _find_col(header, "vulnerability", "cve")
            pkg_col    = _find_col(header, "packages", "package name")
            ver_col    = _find_col(header, "package version", "version")
            fix_col    = _find_col(header, "fix status", "fix")
            img_col    = _find_col(header, "image repository", "repository")
            tag_col    = _find_col(header, "tag")

            for row in rows:
                row_vals = [str(v) for v in row if v is not None]
                if row_vals:
                    texts.append(" | ".join(row_vals))

                # Structured extraction when column layout is recognised.
                if vuln_col is not None and pkg_col is not None and row is not rows[0]:
                    cve_val = str(row[vuln_col]).strip() if row[vuln_col] else ""
                    pkg_val = str(row[pkg_col]).strip() if row[pkg_col] else ""
                    if _CVE_RE.match(cve_val) and pkg_val:
                        pkg_ver = str(row[ver_col]).strip() if ver_col is not None and row[ver_col] else None
                        fix_raw = str(row[fix_col]).strip() if fix_col is not None and row[fix_col] else None
                        packages.append(ExtractedPackage(
                            cve_id=cve_val.upper(),
                            package_name=pkg_val,
                            package_version=pkg_ver if pkg_ver else None,
                            fixed_version=_parse_fix_status(fix_raw),
                            source=source,
                        ))

        full_text = "\n".join(texts)
    except Exception as e:
        return ParsedAttachment(
            attachment_id=attachment_id,
            filename=filename,
            mime_type=mime_type,
            status="error",
            text_preview=str(e)[:1000],
            cves=[],
            images=[],
            packages=[],
        )

    cves = extract_cves(full_text, source)
    images = extract_images(full_text, source)
    return ParsedAttachment(
        attachment_id=attachment_id,
        filename=filename,
        mime_type=mime_type,
        status="ok",
        text_preview=full_text[:2000],
        cves=cves,
        images=images,
        packages=packages,
    )


def parse_attachment_bytes(
    *,
    attachment_id: str,
    filename: str,
    mime_type: str | None,
    data: bytes,
) -> ParsedAttachment:
    source = f"attachment:{attachment_id}:{filename}"
    lower = filename.lower()

    if lower.endswith((".xlsx", ".xlsm", ".xltx", ".xltm")) or mime_type in (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
    ):
        return parse_excel_bytes(data, source, attachment_id, filename, mime_type)

    if lower.endswith(".pdf") or mime_type == "application/pdf":
        return parse_pdf_bytes(data, source, attachment_id, filename, mime_type)

    return ParsedAttachment(
        attachment_id=attachment_id,
        filename=filename,
        mime_type=mime_type,
        status="unparsed",
        text_preview=None,
        cves=[],
        images=[],
        packages=[],
    )


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
    # Fallback: stringify (keeps CVE regex working on unexpected formats)
    return str(description_raw)

