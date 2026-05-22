from __future__ import annotations

import datetime as dt
import json
import re
import uuid
from typing import Any

from sqlalchemy import func

from api.app.config import settings
from api.app.db import db_session
from api.app.jira_client import JiraClient, PlatTicket
from api.app.plat_linking import plat_keys_to_link_for_row, plat_tickets_for_row
from api.app.allowed_images import load_alias_map, normalize_image_basename
from api.app.models import CveCache, CustomerSla, IssueSyncSchedule, ProcessingRun
from api.app.sla_commitment import due_date_from_anchor
from api.app.nvd_client import NvdClient, _extract_affected_packages
from api.app.redhat_client import RedHatClient
from api.app.cve5_client import Cve5Client
from api.app.parsing import extract_cves, extract_images, normalize_description, parse_attachment_bytes
from worker.app.celery_app import celery_app


def _set_run_status(run_id: str, status: str) -> None:
    with db_session() as db:
        run = db.get(ProcessingRun, run_id)
        if run:
            run.status = status
            db.add(run)
            db.commit()


_PLAT_SYNC_PHASE_COUNT = 1


def _write_plat_sync_progress(
    run_id: str,
    *,
    phase: str,
    phase_current: int,
    phase_total: int,
    phase_index: int,
) -> None:
    """Persist in-flight PLAT sync progress into result_json for UI polling."""
    rid = uuid.UUID(run_id)
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run or not run.result_json:
            return
        data = json.loads(run.result_json)
        data["_plat_sync_progress"] = {
            "phase": phase,
            "phase_current": phase_current,
            "phase_total": max(phase_total, 1),
            "phase_index": phase_index,
            "phase_count": _PLAT_SYNC_PHASE_COUNT,
        }
        run.result_json = json.dumps(data)
        db.add(run)
        db.commit()


class _SyncProgressReporter:
    def __init__(self, run_id: str) -> None:
        self._run_id = run_id
        self.phase = "Starting"
        self.phase_current = 0
        self.phase_total = 1
        self.phase_index = 0

    def set_phase(self, phase: str, phase_total: int, phase_index: int) -> None:
        self.phase = phase
        self.phase_total = max(phase_total, 1)
        self.phase_current = 0
        self.phase_index = phase_index
        self._flush()

    def bump(self) -> None:
        self.phase_current += 1
        self._flush()

    def _flush(self) -> None:
        _write_plat_sync_progress(
            self._run_id,
            phase=self.phase,
            phase_current=self.phase_current,
            phase_total=self.phase_total,
            phase_index=self.phase_index,
        )


def _img_tokens(img_name: str) -> list[str]:
    """Return searchable substrings for an image name, e.g. 'plainid/pip-operator' → ['pip-operator','pip','operator']."""
    name = re.sub(r"^plainid/", "", img_name, flags=re.IGNORECASE).lower()
    parts = re.split(r"[-_]", name)
    tokens: list[str] = [name] + parts
    stem = name.split(":", 1)[0].strip() if ":" in name else name
    if stem and stem not in tokens:
        tokens.append(stem)
    # Path segments (e.g. rclone/rclone → bare "rclone") so Bug summaries like [CVE] - [rclone] match.
    for seg in stem.split("/"):
        s = seg.strip()
        if s and s not in tokens:
            tokens.append(s)
    return [t for t in tokens if t]


def _token_in_summary(tok: str, summary_lower: str) -> bool:
    """Match token as a complete segment — not as a prefix/suffix of a longer hyphenated word.
    e.g. 'pip' matches 'pip' and '[pip]' but NOT 'pip-mgmt' or 'pip-operator'."""
    return bool(re.search(r"(?<![a-zA-Z0-9\-_])" + re.escape(tok) + r"(?![a-zA-Z0-9\-_])", summary_lower))


def _filter_plat_tickets(tickets: list[dict], imgs: list[dict]) -> list[dict]:
    """Keep Security Vulnerability tickets as-is; filter Bug tickets to those matching an affected image."""
    img_token_set = {tok for i in imgs for tok in _img_tokens(i["image"]) if len(tok) > 2}
    result = []
    for t in tickets:
        if t["issue_type"] == "Bug" and img_token_set:
            summary_lower = (t.get("summary") or "").lower()
            if not any(_token_in_summary(tok, summary_lower) for tok in img_token_set):
                continue  # no image match — skip this Bug ticket
        result.append(t)
    return result


def _affected_imgs_for_cve_row(row: dict[str, Any]) -> list[dict]:
    """Normalize row `affected_images` (and legacy fields) to list of {image, tag} dicts for PLAT filtering."""
    ai = row.get("affected_images")
    if isinstance(ai, list) and ai:
        out: list[dict] = []
        for x in ai:
            if not isinstance(x, dict):
                continue
            im = (x.get("image") or "").strip()
            if not im:
                continue
            out.append({"image": im, "tag": (x.get("tag") or "")})
        if out:
            return out
    img = row.get("affected_image")
    if img and str(img).strip() and str(img).strip().upper() != "NA":
        return [{"image": str(img).strip(), "tag": row.get("affected_tag") or ""}]
    return []


@celery_app.task(name="process_issue", bind=True)
def process_issue(self, run_id: str, issue_key: str) -> dict[str, Any]:
    # v1 extraction: description + attachments (Excel/PDF) with provenance.
    try:
        _set_run_status(run_id, "fetching_issue")
        jira = JiraClient()
        issue = jira.get_issue(issue_key)

        _set_run_status(run_id, "extracting_from_description")
        desc_text = normalize_description(issue.description_raw)
        desc_cves = extract_cves(desc_text, "description")
        desc_images = extract_images(desc_text, "description")

        _set_run_status(run_id, "downloading_attachments")
        blobs = []
        for a in issue.attachments:
            if not a.get("id") or not a.get("content") or not a.get("filename"):
                continue
            blobs.append((a, jira.download_attachment(a["content"])))

        _set_run_status(run_id, "parsing_attachments")
        with db_session() as db:
            alias_map = load_alias_map(db)
        parsed_attachments = []
        for a, blob in blobs:
            parsed = parse_attachment_bytes(
                attachment_id=str(a["id"]),
                filename=str(a["filename"]),
                mime_type=a.get("mimeType"),
                data=blob,
                alias_map=alias_map,
            )
            parsed_attachments.append(
                {
                    "id": parsed.attachment_id,
                    "filename": parsed.filename,
                    "mimeType": parsed.mime_type,
                    "status": parsed.status,
                    "text_preview": parsed.text_preview,
                    "cves": [{"cve_id": c.cve_id, "source": c.source} for c in parsed.cves],
                    "images": [{"image": i.image, "tag": i.tag, "source": i.source} for i in parsed.images],
                    "packages": [
                        {
                            "cve_id": p.cve_id,
                            "package_name": p.package_name,
                            "package_version": p.package_version,
                            "fixed_version": p.fixed_version,
                        }
                        for p in parsed.packages
                    ],
                    "cve_image_facts": [
                        {"cve_id": f.cve_id, "image": f.image, "tag": f.tag, "source": f.source}
                        for f in parsed.cve_image_facts
                    ],
                }
            )

        cve_ids = sorted({c.cve_id for c in desc_cves} | {c["cve_id"] for p in parsed_attachments for c in p["cves"]})

        images = [{"image": i.image, "tag": i.tag, "source": i.source} for i in desc_images]
        for p in parsed_attachments:
            images.extend(p["images"])

        _set_run_status(run_id, "enriching_nvd")
        nvd = NvdClient()
        try:
            enriched = []
            with db_session() as db:
                for cve_id in cve_ids:
                    cached = db.get(CveCache, cve_id)
                    if cached and cached.state == "ok":
                        # Re-parse packages from cached raw_json.
                        pkgs = []
                        if cached.raw_json:
                            try:
                                raw = json.loads(cached.raw_json)
                                cve_doc = ((raw.get("vulnerabilities") or [{}])[0] or {}).get("cve") or {}
                                pkgs = [
                                    {"vendor": p.vendor, "product": p.product,
                                     "version_start": p.version_start, "fixed_version": p.fixed_version}
                                    for p in _extract_affected_packages(cve_doc)
                                ]
                            except Exception:
                                pass
                        enriched.append(
                            {
                                "cve_id": cve_id,
                                "state": cached.state,
                                "severity": cached.severity,
                                "score": cached.score,
                                "published": cached.published,
                                "modified": cached.modified,
                                "packages": pkgs,
                            }
                        )
                        continue

                    try:
                        nvd_cve = nvd.fetch_cve(cve_id)
                    except Exception:
                        nvd_cve = None

                    if nvd_cve is None:
                        db.merge(CveCache(cve_id=cve_id, state="error"))
                        enriched.append({"cve_id": cve_id, "state": "error"})
                    else:
                        db.merge(
                            CveCache(
                                cve_id=nvd_cve.cve_id,
                                state=nvd_cve.state,
                                severity=nvd_cve.severity,
                                score=nvd_cve.score,
                                published=nvd_cve.published,
                                modified=nvd_cve.modified,
                                raw_json=nvd_cve.raw_json,
                            )
                        )
                        enriched.append(
                            {
                                "cve_id": nvd_cve.cve_id,
                                "state": nvd_cve.state,
                                "severity": nvd_cve.severity,
                                "score": nvd_cve.score,
                                "published": nvd_cve.published,
                                "modified": nvd_cve.modified,
                                "packages": [
                                    {"vendor": p.vendor, "product": p.product,
                                     "version_start": p.version_start, "fixed_version": p.fixed_version}
                                    for p in nvd_cve.affected_packages
                                ],
                            }
                        )
                db.commit()
        finally:
            nvd.close()

        if settings.redhat_enrichment_enabled:
            _set_run_status(run_id, "enriching_rh")
            rh = RedHatClient()
            try:
                for entry in enriched:
                    # Only call Red Hat when NVD is missing packages or severity/score.
                    if entry.get("packages") and entry.get("severity") and entry.get("score"):
                        continue
                    rh_cve = rh.fetch_cve(entry["cve_id"])
                    if not rh_cve:
                        continue
                    if not entry.get("packages") and rh_cve.packages:
                        entry["packages"] = rh_cve.packages
                    if not entry.get("severity") and rh_cve.severity:
                        entry["severity"] = rh_cve.severity
                    if not entry.get("score") and rh_cve.score:
                        entry["score"] = rh_cve.score
            finally:
                rh.close()

        # 3rd fallback: MITRE CVE 5.0 API — authoritative CNA version ranges.
        # NVD's CPE layer sometimes drops version info that the CNA published in CVE 5.0 JSON.
        # Enabled via CVE5_ENRICHMENT_ENABLED=true (disabled by default).
        if settings.cve5_enrichment_enabled:
            _set_run_status(run_id, "enriching_cve5")
            cve5 = Cve5Client()
            try:
                for entry in enriched:
                    if entry.get("packages") and all(
                        p.get("version_start") or p.get("fixed_version")
                        for p in entry["packages"]
                    ):
                        continue
                    cve5_result = cve5.fetch_cve(entry["cve_id"])
                    if not cve5_result or not cve5_result.packages:
                        continue
                    if not entry.get("packages"):
                        entry["packages"] = cve5_result.packages
                    else:
                        # Merge: fill in missing version_start / fixed_version from CVE 5.0
                        cve5_by_product = {
                            p["product"].lower(): p for p in cve5_result.packages
                        }
                        for pkg in entry["packages"]:
                            c5 = cve5_by_product.get((pkg.get("product") or "").lower())
                            if not c5:
                                continue
                            if not pkg.get("version_start") and c5.get("version_start"):
                                pkg["version_start"] = c5["version_start"]
                            if not pkg.get("fixed_version") and c5.get("fixed_version"):
                                pkg["fixed_version"] = c5["fixed_version"]
            finally:
                cve5.close()

        # 4th fallback: fill missing packages / versions from ticket attachment columns
        # ("Package Version" and "Fix Status").  Unlike the API fallbacks, ticket data
        # is also merged into existing NVD package entries to fill missing version fields.
        ticket_pkgs: dict[str, list[dict[str, Any]]] = {}
        for att in parsed_attachments:
            for p in att.get("packages") or []:
                cve = (p.get("cve_id") or "").strip().upper()
                if not cve:
                    continue
                ticket_pkgs.setdefault(cve, []).append({
                    "vendor": "ticket",
                    "product": (p.get("package_name") or "").strip(),
                    "version_start": (p.get("package_version") or "").strip() or None,
                    "fixed_version": (p.get("fixed_version") or "").strip() or None,
                })
        for entry in enriched:
            t_pkgs = ticket_pkgs.get(entry["cve_id"])
            if not t_pkgs:
                continue
            t_with_product = [p for p in t_pkgs if p.get("product")]
            if not t_with_product:
                continue
            if not entry.get("packages"):
                # No packages from online sources — use ticket data wholesale.
                entry["packages"] = list(t_with_product)
            else:
                # Merge ticket version fields into NVD entries with matching product names.
                t_by_product = {p["product"].lower(): p for p in t_with_product}
                matched_ticket: set[str] = set()
                for pkg in entry["packages"]:
                    tp = t_by_product.get((pkg.get("product") or "").lower())
                    if not tp:
                        continue
                    matched_ticket.add(tp["product"].lower())
                    if not pkg.get("version_start") and tp.get("version_start"):
                        pkg["version_start"] = tp["version_start"]
                    if not pkg.get("fixed_version") and tp.get("fixed_version"):
                        pkg["fixed_version"] = tp["fixed_version"]
                # No name match (e.g. NVD "gnutls" vs scan "libgnutls30") — primary
                # row fields come from the attachment, not NVD metadata.
                if not matched_ticket:
                    tp = t_with_product[0]
                    entry["attachment_primary"] = {
                        "product": tp["product"],
                        "version_start": tp.get("version_start"),
                        "fixed_version": tp.get("fixed_version"),
                    }


        # Look up associated PLAT tickets (Security Vulnerability + Bug) for each CVE.
        _set_run_status(run_id, "looking_up_plat_tickets")
        cve_to_plat: dict[str, list[dict]] = {}
        cve_to_plat_security_by_image: dict[str, dict[str, list[str]]] = {}
        cve_to_plat_bugs: dict[str, list[dict[str, str]]] = {}
        try:
            for cve_id in cve_ids:
                try:
                    tickets: list[PlatTicket] = jira.search_plat_tickets(cve_id)
                    cve_to_plat[cve_id] = [
                        {"key": t.key, "issue_type": t.issue_type, "summary": t.summary}
                        for t in tickets
                    ]
                    by_img: dict[str, list[str]] = {}
                    for item in jira.search_plat_security_for_cve(cve_id):
                        img = (item.get("image_basename") or "").strip()
                        if not img:
                            continue
                        by_img.setdefault(img, []).append(item["key"])
                    cve_to_plat_security_by_image[cve_id] = by_img
                    cve_to_plat_bugs[cve_id] = jira.search_plat_bugs_for_cve(cve_id)
                except Exception:
                    cve_to_plat[cve_id] = []
                    cve_to_plat_security_by_image[cve_id] = {}
                    cve_to_plat_bugs[cve_id] = []
        finally:
            jira.close()

        nvd_by_id = {e["cve_id"]: e for e in enriched}

        def _ver_tuple(v: str | None) -> tuple:
            if not v:
                return ()
            try:
                return tuple(int(x) for x in v.split("."))
            except ValueError:
                return ()

        def _dedup_packages(pkgs: list[dict]) -> list[dict]:
            """Collapse same-product entries, keeping the one with the highest fixed_version."""
            seen: dict[str, dict] = {}
            for p in pkgs:
                key = p.get("product", "")
                existing = seen.get(key)
                if not existing or _ver_tuple(p.get("fixed_version")) > _ver_tuple(existing.get("fixed_version")):
                    seen[key] = p
            return list(seen.values())

        def _pick_best_nvd_package(pkgs: list[dict]) -> dict | None:
            if not pkgs:
                return None
            for p in pkgs:
                if p.get("version_start"):
                    return p
            for p in pkgs:
                if p.get("fixed_version"):
                    return p
            return pkgs[0]

        # Build PlainID image filter from configurable token list.
        _plainid_tokens = tuple(
            t.strip().lower()
            for t in settings.plainid_image_patterns.split(",")
            if t.strip()
        )
        # Always accept images whose path starts with "plainid/".
        _plainid_tokens = _plainid_tokens + ("plainid",)
        # Any canonical name in the Allowed Images catalog is a known PlainID image
        # (covers resolved Aqua aliases like "secrets-mgmt" that don't match token patterns).
        _allowed_canonical: set[str] = set(alias_map.values())

        def _is_plainid_image(image_name: str) -> bool:
            lower = image_name.lower()
            return lower in _allowed_canonical or any(tok in lower for tok in _plainid_tokens)

        # Build cve_to_images from CveImageFacts (structured per-row links) first.
        # This avoids fragile cross-attachment correlation.
        cve_to_images: dict[str, list[dict]] = {c: [] for c in cve_ids}
        seen_img_keys: set[tuple[str, str, str]] = set()  # (cve_id, image, tag)

        # 1. Structured facts from Excel (direct CVE ↔ image mapping per row).
        for p in parsed_attachments:
            for fact in p.get("cve_image_facts", []):
                if not _is_plainid_image(fact["image"]):
                    continue
                key = (fact["cve_id"], fact["image"], fact["tag"])
                if fact["cve_id"] in cve_to_images and key not in seen_img_keys:
                    seen_img_keys.add(key)
                    cve_to_images[fact["cve_id"]].append(
                        {"image": fact["image"], "tag": fact["tag"], "source": fact["source"]}
                    )

        def _resolve_image_name(raw: str) -> str:
            """Normalize raw image path → canonical name via alias map, or best-effort basename."""
            basename = normalize_image_basename(raw)
            return alias_map.get(basename, basename)

        # 2. Legacy: free-text images from description apply to all CVEs in description.
        desc_cve_ids = {c.cve_id for c in desc_cves}
        for i in desc_images:
            if not _is_plainid_image(i.image):
                continue
            canonical = _resolve_image_name(i.image)
            for cve_id in desc_cve_ids:
                if cve_id not in cve_to_images:
                    continue
                key = (cve_id, canonical, i.tag)
                if key not in seen_img_keys:
                    seen_img_keys.add(key)
                    cve_to_images[cve_id].append({"image": canonical, "tag": i.tag, "source": i.source})

        # 3. Legacy: free-text images from attachments (when no structured facts were extracted).
        #    Correlate by CVEs found in the same attachment.
        for p in parsed_attachments:
            if p.get("cve_image_facts"):
                continue  # structured extraction succeeded — skip legacy correlation
            att_cves = {c["cve_id"] for c in p["cves"]}
            for img_dict in p.get("images", []):
                if not _is_plainid_image(img_dict["image"]):
                    continue
                canonical = _resolve_image_name(img_dict["image"])
                for cve_id in att_cves:
                    if cve_id not in cve_to_images:
                        continue
                    key = (cve_id, canonical, img_dict["tag"])
                    if key not in seen_img_keys:
                        seen_img_keys.add(key)
                        cve_to_images[cve_id].append({**img_dict, "image": canonical})

        _set_run_status(run_id, "building_results")

        cve_rows = []
        for cve_id in cve_ids:
            nvd_entry = nvd_by_id.get(cve_id, {})
            imgs = cve_to_images.get(cve_id, [])

            # Package/resource metadata priority: NVD CPE → Red Hat errata → MITRE CVE 5.0 → ticket attachments.
            # The enrichment phases above (enriching_nvd, enriching_rh, ticket fallback) populate
            # entry["packages"] in that priority order before we reach this point.
            nvd_pkgs: list[dict] = _dedup_packages(nvd_entry.get("packages") or [])
            attach_primary = nvd_entry.get("attachment_primary")
            if attach_primary:
                primary = attach_primary
            elif nvd_pkgs:
                primary = _pick_best_nvd_package(nvd_pkgs)
            else:
                primary = None
            affected_resource = primary.get("product") if primary else None
            affected_version = primary.get("version_start") if primary else None
            fixed_version = primary.get("fixed_version") if primary else None
            all_packages = nvd_pkgs

            raw_plat = cve_to_plat.get(cve_id, [])
            plat_security_keys = [
                t["key"] for t in raw_plat if t["issue_type"] == "Security Vulnerability"
            ]
            plat_security_for_images = dict(cve_to_plat_security_by_image.get(cve_id, {}))
            row_for_plat = {
                "cve_id": cve_id,
                "affected_images": [{"image": i["image"], "tag": i["tag"]} for i in imgs],
            }
            plat_tickets = plat_tickets_for_row(
                cve_id,
                raw_plat,
                row_for_plat,
                cve_to_plat_bugs.get(cve_id),
            )

            cve_rows.append(
                {
                    "cve_id": cve_id,
                    "severity": nvd_entry.get("severity"),
                    "score": nvd_entry.get("score"),
                    "nvd_state": nvd_entry.get("state", "unknown"),
                    # All matched PlainID images for this CVE (may be multiple).
                    "affected_images": [{"image": i["image"], "tag": i["tag"]} for i in imgs],
                    # Legacy single-image fields kept for backward compatibility.
                    "affected_image": imgs[0]["image"] if imgs else "NA",
                    "affected_tag": imgs[0]["tag"] if imgs else None,
                    "affected_resource": affected_resource,
                    "affected_version": affected_version,
                    "fixed_version": fixed_version,
                    "all_packages": all_packages,
                    "plat_security_keys": plat_security_keys,
                    "plat_security_for_images": plat_security_for_images,
                    "plat_tickets": plat_tickets,
                    "sources": list(
                        {c.source for c in desc_cves if c.cve_id == cve_id}
                        | {c["source"] for p in parsed_attachments for c in p["cves"] if c["cve_id"] == cve_id}
                    ),
                }
            )

        rows_by_customer_lower: dict[str, dict[str, Any]] = {}
        with db_session() as db:
            for row in db.query(CustomerSla).all():
                nm = (row.customer_name or "").strip()
                if not nm:
                    continue
                rows_by_customer_lower[nm.casefold()] = {
                    "sla_critical": row.sla_critical,
                    "sla_high": row.sla_high,
                    "sla_medium": row.sla_medium,
                    "sla_low": row.sla_low,
                }

        anchor = issue.created
        org_names = list(issue.organizations or [])
        for row in cve_rows:
            row["sla_due_date"] = due_date_from_anchor(
                anchor,
                org_names,
                row.get("severity"),
                rows_by_customer_lower,
            )

        link_counts: dict[str, Any] = {"links_checked": 0, "links_created": 0, "errors": []}
        if issue.key:
            _jira_link = JiraClient()
            try:
                link_counts = _link_plat_rows(_jira_link, cve_rows, issue.key)
            finally:
                _jira_link.close()

        for entry in enriched:
            entry.pop("attachment_primary", None)

        result = {
            "issue_key": issue.key,
            "sla_anchor_issue_key": issue.key,
            "sla_anchor_created": anchor.isoformat() if anchor else None,
            "organizations": org_names,
            "cves": cve_ids,
            "cve_rows": cve_rows,
            "nvd": enriched,
            "cve_sources": [{"cve_id": c.cve_id, "source": c.source} for c in desc_cves]
            + [c for p in parsed_attachments for c in p["cves"]],
            "attachments": parsed_attachments,
            "images": images,
            "_plat_link_counts": link_counts,
        }
    except Exception as e:
        import traceback
        err_msg = str(e)
        tb_str = traceback.format_exc()
        with db_session() as db:
            run = db.get(ProcessingRun, uuid.UUID(run_id))
            if run:
                run.status = f"failed: {type(e).__name__}"[:32]
                run.result_json = json.dumps({
                    "error": err_msg,
                    "traceback": tb_str
                })
                db.add(run)
                db.commit()
        raise

    with db_session() as db:
        run = db.get(ProcessingRun, run_id)
        if run:
            run.status = "done"
            run.result_json = json.dumps(result)
            db.add(run)
            db.commit()

    return result


def _do_link(
    jira: JiraClient,
    plat_key: str,
    source_issue_key: str,
    seen: set[str],
    counts: dict[str, Any],
) -> None:
    """Link plat_key to source_issue_key once, recording checked vs created in counts."""
    pk = (plat_key or "").strip().upper()
    if not pk or pk in seen:
        return
    seen.add(pk)
    result = jira.ensure_plat_linked_to_parent(pk, source_issue_key)
    counts["links_checked"] += 1
    if result.created:
        counts["links_created"] += 1
    elif result.error_warning:
        counts["errors"].append(result.error_warning)


def _link_plat_rows(
    jira: JiraClient,
    cve_rows: list[dict[str, Any]],
    source_issue_key: str,
    *,
    progress: _SyncProgressReporter | None = None,
) -> dict[str, Any]:
    """
    Link PLAT tickets to source_issue_key for each extracted CVE+image basename
    (same logic as Create PLAT API: find_plat_*_for_image).
    Returns counts: {"links_checked": N, "links_created": N, "errors": [...]}
    """
    counts: dict[str, Any] = {"links_checked": 0, "links_created": 0, "errors": []}
    seen: set[str] = set()
    for row in cve_rows:
        for pk in plat_keys_to_link_for_row(jira, row):
            _do_link(jira, pk, source_issue_key, seen, counts)
            if progress:
                progress.bump()
    return counts


def _plat_sec_keys_for_row(row: dict[str, Any]) -> set[str]:
    s: set[str] = set()
    for k in row.get("plat_security_keys") or []:
        if isinstance(k, str) and k.strip():
            s.add(k.strip().upper())
    for vs in (row.get("plat_security_for_images") or {}).values():
        for k in vs or []:
            if isinstance(k, str) and k.strip():
                s.add(k.strip().upper())
    for t in row.get("plat_tickets") or []:
        if t.get("issue_type") == "Security Vulnerability" and t.get("key"):
            s.add(str(t["key"]).strip().upper())
    return s


@celery_app.task(name="sync_plat_for_run")
def sync_plat_for_run(run_id: str) -> dict[str, Any]:
    """Re-fetch PLAT Security issue fields into cve_rows."""
    rid = uuid.UUID(run_id)
    _set_run_status(run_id, "syncing_plat")
    try:
        with db_session() as db:
            run = db.get(ProcessingRun, rid)
            if not run or not run.result_json:
                raise ValueError("run has no stored result")
            result = json.loads(run.result_json)
            source_issue_key: str = (run.issue_key or "").strip()
        cve_rows: list[dict[str, Any]] = result.get("cve_rows") or []
        if not cve_rows:
            with db_session() as db:
                run = db.get(ProcessingRun, rid)
                if run:
                    run.status = "done"
                    db.add(run)
                    db.commit()
            return result

        jira = JiraClient()
        plat_meta: dict[str, dict[str, Any]] = {}
        sync_errors: list[str] = []
        progress = _SyncProgressReporter(run_id)
        stats: dict[str, Any] = {
            "tickets_refreshed": 0,
            "fields_read": 0,
            "label_date_checked": 0,
            "label_date_updated": 0,
            "labels_added": 0,
            "duedates_updated": 0,
            "links_checked": 0,
            "links_created": 0,
        }
        try:
            # Collect existing Security Vulnerability (PLAT CVE) keys from cve_rows
            all_keys: set[str] = set()
            for row in cve_rows:
                all_keys |= _plat_sec_keys_for_row(row)

            progress.set_phase("Reading fix/tag from Jira", len(all_keys), 1)

            for pk in sorted(all_keys):
                try:
                    m = jira.get_issue_platsync_fields(pk)
                    if m:
                        plat_meta[pk] = m
                        stats["fields_read"] += 1
                except Exception as ex:
                    sync_errors.append(f"{pk} read field error: {ex}")
                progress.bump()

            # Update plat_security_field_sync mapping on each row with the retrieved values
            for row in cve_rows:
                row.pop("plat_app_fix_versions", None)
                row.pop("plat_tag_numbers", None)
                sync_map: dict[str, dict[str, str]] = {}
                for pk in _plat_sec_keys_for_row(row):
                    m = plat_meta.get(pk)
                    if not m:
                        continue
                    fix_s = (m.get("fix_versions") or "").strip()
                    tag_s = (m.get("tag_numbers") or "").strip()
                    sync_map[pk] = {
                        "fix_versions": fix_s if fix_s else "None",
                        "tag_numbers": tag_s if tag_s else "None",
                    }
                if sync_map:
                    row["plat_security_field_sync"] = sync_map
                else:
                    row.pop("plat_security_field_sync", None)

        finally:
            jira.close()

        if sync_errors:
            result["_plat_sync_errors"] = sync_errors
        else:
            result.pop("_plat_sync_errors", None)
        result.pop("_plat_sync_progress", None)
        result["_plat_sync_stats"] = stats
        result["cve_rows"] = cve_rows
        with db_session() as db:
            run = db.get(ProcessingRun, rid)
            if run:
                run.status = "done"
                run.result_json = json.dumps(result)
                db.add(run)
                db.commit()
        return result
    except Exception as e:
        import traceback
        err_msg = str(e)
        tb_str = traceback.format_exc()
        with db_session() as db:
            run = db.get(ProcessingRun, rid)
            if run:
                run.status = f"failed: {type(e).__name__}"[:32]
                try:
                    res = json.loads(run.result_json) if run.result_json else {}
                except Exception:
                    res = {}
                res["error"] = err_msg
                res["traceback"] = tb_str
                run.result_json = json.dumps(res)
                db.add(run)
                db.commit()
        raise


_DAILY_SYNC_INTERVAL = dt.timedelta(hours=24)


@celery_app.task(name="run_due_plat_syncs")
def run_due_plat_syncs() -> dict[str, Any]:
    """Enqueue Sync PLAT for tickets with daily sync enabled and last run > 24h ago."""
    now = dt.datetime.now(dt.UTC)
    enqueued: list[str] = []
    skipped: list[str] = []

    with db_session() as db:
        schedules = (
            db.query(IssueSyncSchedule)
            .filter(IssueSyncSchedule.daily_sync_enabled.is_(True))
            .all()
        )
        schedule_items = [(s.issue_key, s.last_auto_sync_at) for s in schedules]

    for issue_key, last_at in schedule_items:
        if last_at and (now - last_at) < _DAILY_SYNC_INTERVAL:
            skipped.append(issue_key)
            continue

        with db_session() as db:
            run = (
                db.query(ProcessingRun)
                .filter(
                    func.lower(ProcessingRun.issue_key) == issue_key.casefold(),
                    ProcessingRun.status == "done",
                    ProcessingRun.result_json.isnot(None),
                )
                .order_by(ProcessingRun.created_at.desc())
                .first()
            )
            if not run:
                skipped.append(issue_key)
                continue

        sync_plat_for_run.delay(str(run.id))
        with db_session() as db:
            row = db.get(IssueSyncSchedule, issue_key)
            if row:
                row.last_auto_sync_at = now
                db.add(row)
                db.commit()
        enqueued.append(issue_key)

    return {"enqueued": enqueued, "skipped": skipped, "checked_at": now.isoformat()}

