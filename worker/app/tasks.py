from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

from sqlalchemy import func

from api.app.config import settings
from api.app.db import db_session
from api.app.jira_client import JiraClient, PlatSearchError
from api.app.plat_audit import log_plat_audit
from api.app.plat_linking import (
    link_plat_key_to_parent,
    plat_keys_to_link_for_row,
    plat_security_by_image_from_search,
    plat_tickets_for_row,
)
from api.app.allowed_images import load_alias_map, normalize_image_basename
from api.app.models import CveCache, CustomerSla, IssueSyncSchedule, ProcessingRun
from api.app.sla_commitment import due_date_from_anchor
from api.app.nvd_client import NvdClient, _extract_affected_packages
from api.app.alpine_client import AlpineClient
from api.app.redhat_client import RedHatClient
from api.app.cve5_client import Cve5Client
from api.app.parsing import (
    cve_ids_from_attachment_facts,
    extract_cves,
    extract_images,
    is_cve_id,
    is_ghsa_id,
    list_excel_sheets,
    normalize_description,
    parse_attachment_bytes,
    severity_rank,
)
from api.app.aqua_client import AquaClient
from api.app.aqua_packages import candidates_to_json, cross_check_package, resolve_aqua_search_name
from api.app.portal_settings import (
    get_aqua_default_image_tag,
    get_aqua_processing_enabled,
    get_rewrite_plat_package_name_on_sync,
)
from api.app.package_name import canonical_single_package_name
from api.app.cve_row_derived import (
    _image_path_basename,
    apply_plat_vendor_fields_from_sync,
    image_basenames_for_cve_row,
    iter_plat_security_package_targets,
    plat_issue_status_is_invalid,
    plat_jira_package_name_for_row,
    plat_sec_keys_scoped_to_run,
)
from worker.app.celery_app import celery_app


def _set_run_status(run_id: str, status: str) -> None:
    with db_session() as db:
        run = db.get(ProcessingRun, run_id)
        if run:
            run.status = status
            db.add(run)
            db.commit()


_PLAT_SYNC_PHASE_COUNT = 1
_PLAT_SYNC_LOG_MAX = 150


def _init_plat_sync_log(run_id: str) -> None:
    """Clear in-flight PLAT sync activity log (UI + worker stdout)."""
    rid = uuid.UUID(run_id)
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run or not run.result_json:
            return
        data = json.loads(run.result_json)
        data["_plat_sync_log"] = []
        run.result_json = json.dumps(data)
        db.add(run)
        db.commit()


def _append_plat_sync_log(run_id: str, level: str, msg: str) -> None:
    """Append one line to _plat_sync_log in result_json for UI polling."""
    text = (msg or "").strip()
    if not text:
        return
    lvl = (level or "info").strip().lower()
    if lvl not in ("info", "warn", "error"):
        lvl = "info"
    entry = {
        "ts": dt.datetime.now(dt.UTC).isoformat(),
        "level": lvl,
        "msg": text,
    }
    logger.log(
        logging.WARNING if lvl == "warn" else logging.ERROR if lvl == "error" else logging.INFO,
        "plat_sync run_id=%s %s",
        run_id,
        text,
    )
    rid = uuid.UUID(run_id)
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run or not run.result_json:
            return
        data = json.loads(run.result_json)
        log = data.get("_plat_sync_log")
        if not isinstance(log, list):
            log = []
        log.append(entry)
        if len(log) > _PLAT_SYNC_LOG_MAX:
            log = log[-_PLAT_SYNC_LOG_MAX:]
        data["_plat_sync_log"] = log
        run.result_json = json.dumps(data)
        db.add(run)
        db.commit()


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


def _is_excel_attachment(filename: str, mime_type: str | None) -> bool:
    lower = (filename or "").lower()
    if lower.endswith((".xlsx", ".xlsm", ".xltx", ".xltm")):
        return True
    return mime_type in (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
    )


def _normalize_sheet_selection(sheet_selection: dict[str, Any] | None) -> dict[str, set[str]]:
    """Map attachment_id → selected sheet names.

    Accepts either:
      {"att-id": ["Sheet A", "Sheet B"]}
    or
      {"selections": [{"attachment_id": "att-id", "sheets": ["Sheet A"]}]}
    """
    if not sheet_selection:
        return {}
    out: dict[str, set[str]] = {}
    if isinstance(sheet_selection.get("selections"), list):
        for item in sheet_selection["selections"]:
            if not isinstance(item, dict):
                continue
            aid = str(item.get("attachment_id") or "").strip()
            sheets = item.get("sheets") or []
            if not aid or not isinstance(sheets, list):
                continue
            names = {str(s).strip() for s in sheets if str(s).strip()}
            if names:
                out[aid] = names
        return out
    for aid, sheets in sheet_selection.items():
        if aid == "selections":
            continue
        if not isinstance(sheets, list):
            continue
        names = {str(s).strip() for s in sheets if str(s).strip()}
        if names:
            out[str(aid)] = names
    return out


def _apply_ghsa_aliases(
    parsed_attachments: list[dict],
    advisory_by_ghsa: dict[str, Any],
) -> dict[str, str]:
    """Rewrite GHSA facts to CVE when GitHub reports a CVE alias.

    Returns mapping of rewritten GHSA → CVE for provenance.
    """
    aliases: dict[str, str] = {}
    for ghsa_id, adv in advisory_by_ghsa.items():
        cve_alias = getattr(adv, "cve_id", None) or (adv.get("cve_id") if isinstance(adv, dict) else None)
        if cve_alias and is_cve_id(cve_alias):
            aliases[ghsa_id.upper()] = str(cve_alias).upper()

    if not aliases:
        return {}

    for p in parsed_attachments:
        for fact in p.get("cve_image_facts") or []:
            cid = (fact.get("cve_id") or "").upper()
            if cid in aliases:
                fact["ghsa_id"] = cid
                fact["cve_id"] = aliases[cid]
        for pkg in p.get("packages") or []:
            cid = (pkg.get("cve_id") or "").upper()
            if cid in aliases:
                pkg["ghsa_id"] = cid
                pkg["cve_id"] = aliases[cid]
        for c in p.get("cves") or []:
            cid = (c.get("cve_id") or "").upper()
            if cid in aliases:
                c["ghsa_id"] = cid
                c["cve_id"] = aliases[cid]
    return aliases


@celery_app.task(name="process_issue", bind=True)
def process_issue(
    self,
    run_id: str,
    issue_key: str,
    sheet_selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Extraction: description scraped for provenance; findings CVEs from attachment facts only.
    try:
        selection_map = _normalize_sheet_selection(sheet_selection)

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

        # Multi-sheet Excel: pause for operator sheet selection unless already provided.
        if not selection_map:
            sheet_choices: list[dict[str, Any]] = []
            needs_selection = False
            for a, blob in blobs:
                fname = str(a["filename"])
                mime = a.get("mimeType")
                if not _is_excel_attachment(fname, mime):
                    continue
                try:
                    sheets = list_excel_sheets(blob)
                except Exception:
                    sheets = []
                entry = {
                    "attachment_id": str(a["id"]),
                    "filename": fname,
                    "sheets": sheets,
                }
                sheet_choices.append(entry)
                if len(sheets) > 1:
                    needs_selection = True

            if needs_selection:
                pause_payload = {
                    "issue_key": issue.key,
                    "sheet_choices": sheet_choices,
                    "awaiting_sheet_selection": True,
                }
                with db_session() as db:
                    run = db.get(ProcessingRun, uuid.UUID(run_id))
                    if run:
                        run.status = "awaiting_sheet_selection"
                        run.result_json = json.dumps(pause_payload)
                        db.add(run)
                        db.commit()
                return pause_payload

        _set_run_status(run_id, "parsing_attachments")
        with db_session() as db:
            alias_map = load_alias_map(db)
        parsed_attachments = []
        for a, blob in blobs:
            aid = str(a["id"])
            fname = str(a["filename"])
            mime = a.get("mimeType")
            sheets_for_att: set[str] | None = None
            if selection_map and _is_excel_attachment(fname, mime):
                if aid in selection_map:
                    sheets_for_att = selection_map[aid]
                else:
                    # Resume path: multi-sheet workbooks must be in selection_map.
                    # Avoid a second full-sheet scan (memory) when selection is present.
                    try:
                        meta = list_excel_sheets(blob)
                    except Exception:
                        meta = []
                    if len(meta) > 1:
                        sheets_for_att = set()
            elif aid in selection_map:
                sheets_for_att = selection_map[aid]
            logger.info(
                "parsing attachment %s (%s) sheets=%s bytes=%s",
                aid,
                fname,
                sorted(sheets_for_att) if sheets_for_att is not None else None,
                len(blob),
            )
            parsed = parse_attachment_bytes(
                attachment_id=aid,
                filename=fname,
                mime_type=mime,
                data=blob,
                alias_map=alias_map,
                sheet_names=sheets_for_att,
            )
            logger.info(
                "parsed attachment %s status=%s facts=%s",
                aid,
                parsed.status,
                len(parsed.cve_image_facts),
            )
            parsed_attachments.append(
                {
                    "id": parsed.attachment_id,
                    "filename": parsed.filename,
                    "mimeType": parsed.mime_type,
                    "status": parsed.status,
                    "text_preview": parsed.text_preview,
                    "selected_sheets": sorted(sheets_for_att) if sheets_for_att is not None else None,
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
                        {
                            "cve_id": f.cve_id,
                            "image": f.image,
                            "tag": f.tag,
                            "source": f.source,
                            "severity": f.severity,
                            "score": f.score,
                        }
                        for f in parsed.cve_image_facts
                    ],
                }
            )

        # Resolve GHSA → CVE aliases via GitHub Advisory API before building findings IDs.
        ghsa_ids = sorted(
            {
                f["cve_id"]
                for p in parsed_attachments
                for f in (p.get("cve_image_facts") or [])
                if is_ghsa_id(f.get("cve_id") or "")
            }
        )
        advisory_by_ghsa: dict[str, Any] = {}
        if ghsa_ids:
            logger.info("resolving %s GHSA id(s) via GitHub Advisory API", len(ghsa_ids))
            try:
                from api.app.github_advisory_client import GithubAdvisoryClient

                gh = GithubAdvisoryClient()
                try:
                    for gid in ghsa_ids:
                        advisory_by_ghsa[gid] = gh.fetch(gid)
                finally:
                    gh.close()
                _apply_ghsa_aliases(parsed_attachments, advisory_by_ghsa)
            except Exception:
                logger.exception("GHSA enrichment failed; continuing with raw GHSA ids")

        # CVE/GHSA source of truth: structured attachment facts only (Excel / Aqua JSON).
        # Description and PDF free-text may still be scraped for provenance below, but
        # they must not create findings rows (e.g. CVE-2026-41992 listed in description
        # but absent from the Aqua JSON on PLATFORM-2107).
        cve_ids = cve_ids_from_attachment_facts(parsed_attachments)

        images = [{"image": i.image, "tag": i.tag, "source": i.source} for i in desc_images]
        for p in parsed_attachments:
            images.extend(p["images"])

        _set_run_status(run_id, "enriching_nvd")
        nvd = NvdClient()
        try:
            enriched = []
            with db_session() as db:
                for cve_id in cve_ids:
                    # GHSA-only findings: enrich from GitHub Advisory (already fetched), skip NVD.
                    if is_ghsa_id(cve_id):
                        adv = advisory_by_ghsa.get(cve_id)
                        if adv is None:
                            from api.app.github_advisory_client import GithubAdvisoryClient

                            gh = GithubAdvisoryClient()
                            try:
                                adv = gh.fetch(cve_id)
                            finally:
                                gh.close()
                            advisory_by_ghsa[cve_id] = adv
                        if getattr(adv, "state", None) == "ok":
                            db.merge(
                                CveCache(
                                    cve_id=cve_id,
                                    state="ok",
                                    severity=adv.severity,
                                    score=adv.score,
                                    published=adv.published,
                                    modified=adv.modified,
                                    raw_json=adv.raw_json,
                                )
                            )
                            enriched.append(
                                {
                                    "cve_id": cve_id,
                                    "state": "ok",
                                    "severity": adv.severity,
                                    "score": adv.score,
                                    "published": adv.published,
                                    "modified": adv.modified,
                                    "packages": list(adv.packages or []),
                                    "ghsa_id": cve_id,
                                    "enrichment_source": "github_advisory",
                                }
                            )
                        else:
                            db.merge(CveCache(cve_id=cve_id, state=getattr(adv, "state", None) or "error"))
                            enriched.append(
                                {
                                    "cve_id": cve_id,
                                    "state": getattr(adv, "state", None) or "error",
                                    "ghsa_id": cve_id,
                                    "enrichment_source": "github_advisory",
                                }
                            )
                        continue

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

        if settings.alpine_enrichment_enabled:
            _set_run_status(run_id, "enriching_alpine")
            alpine = AlpineClient()
            try:
                for entry in enriched:
                    if is_ghsa_id(entry.get("cve_id") or ""):
                        continue
                    pkgs = entry.get("packages") or []
                    if pkgs and any((p.get("product") or "").strip() for p in pkgs if isinstance(p, dict)):
                        continue
                    alpine_pkgs = alpine.fetch_cve_packages(entry["cve_id"])
                    if alpine_pkgs:
                        entry["packages"] = alpine_pkgs
            finally:
                alpine.close()

        if settings.redhat_enrichment_enabled:
            _set_run_status(run_id, "enriching_rh")
            rh = RedHatClient()
            try:
                for entry in enriched:
                    if is_ghsa_id(entry.get("cve_id") or ""):
                        continue
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
                    if is_ghsa_id(entry.get("cve_id") or ""):
                        continue
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

        # Ticket attachment fallback: package name only when NVD + Alpine left packages empty;
        # version fields may still be merged from attachment when missing.
        ticket_pkgs: dict[str, list[dict[str, Any]]] = {}
        for att in parsed_attachments:
            for p in att.get("packages") or []:
                cve = (p.get("cve_id") or "").strip().upper()
                if not cve:
                    continue
                ticket_pkgs.setdefault(cve, []).append({
                    "vendor": "ticket",
                    "product": canonical_single_package_name((p.get("package_name") or "").strip()) or "",
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
                entry["packages"] = list(t_with_product)
            else:
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
                if not matched_ticket and t_with_product:
                    tp = t_with_product[0]
                    for pkg in entry["packages"]:
                        if not isinstance(pkg, dict):
                            continue
                        if not pkg.get("version_start") and tp.get("version_start"):
                            pkg["version_start"] = tp["version_start"]
                        if not pkg.get("fixed_version") and tp.get("fixed_version"):
                            pkg["fixed_version"] = tp["fixed_version"]
                        break


        # Look up associated PLAT Security Vulnerability tickets for each CVE.
        _set_run_status(run_id, "looking_up_plat_tickets")
        cve_to_plat: dict[str, list[dict]] = {}
        cve_to_plat_security_by_image: dict[str, dict[str, list[str]]] = {}
        issue_key = (issue.key or "").strip()
        try:
            for cve_id in cve_ids:
                search_results = jira.search_plat_security_for_cve(cve_id)
                all_keys = [item["key"] for item in search_results if item.get("key")]
                by_img, unmapped = plat_security_by_image_from_search(search_results)
                cve_to_plat[cve_id] = [
                    {"key": k, "issue_type": "Security Vulnerability", "summary": None}
                    for k in all_keys
                ]
                cve_to_plat_security_by_image[cve_id] = by_img
                log_plat_audit(
                    "plat_lookup_audit",
                    issue_key=issue_key,
                    run_id=run_id,
                    cve_id=cve_id,
                    search_count=len(search_results),
                    hits=all_keys,
                    by_image=by_img,
                    unmapped_keys=unmapped,
                    decision="ok",
                )
        except PlatSearchError as exc:
            log_plat_audit(
                "plat_lookup_audit",
                issue_key=issue_key,
                run_id=run_id,
                cve_id=getattr(exc, "cve_id", ""),
                decision="search_failed",
                error=str(exc),
            )
            raise
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

        def _resolve_image_name(raw: str) -> str:
            """Normalize raw image path → canonical name via alias map, or best-effort basename."""
            basename = normalize_image_basename(raw)
            return alias_map.get(basename, basename)

        # CVE↔image source of truth: same structured facts that define cve_ids above.
        # Description and PDF free-text are excluded from PLAT image slots — substring
        # token matching (plainid_image_patterns) was unreliable and let bare words like
        # "authorizer" produce PLAT tickets with bad image names.
        # Catalog enforcement (Allowed Images) is applied at PLAT create time (POST /api/plat).
        cve_to_images: dict[str, list[dict]] = {c: [] for c in cve_ids}
        seen_img_keys: set[tuple[str, str, str]] = set()  # (cve_id, image, tag)
        customer_sev_by_cve: dict[str, str] = {}
        customer_score_by_cve: dict[str, str] = {}

        for p in parsed_attachments:
            for fact in p.get("cve_image_facts", []):
                cve_id = fact.get("cve_id") or ""
                if cve_id not in cve_to_images:
                    continue
                canonical = _resolve_image_name(fact["image"])
                key = (cve_id, canonical, fact["tag"])
                if key not in seen_img_keys:
                    seen_img_keys.add(key)
                    cve_to_images[cve_id].append(
                        {"image": canonical, "tag": fact["tag"], "source": fact["source"]}
                    )
                fact_sev = (fact.get("severity") or "").strip().upper() or None
                if fact_sev and severity_rank(fact_sev) > severity_rank(customer_sev_by_cve.get(cve_id)):
                    customer_sev_by_cve[cve_id] = fact_sev
                    fact_score = fact.get("score")
                    if fact_score:
                        customer_score_by_cve[cve_id] = str(fact_score)
                elif (
                    fact_sev
                    and fact_sev == customer_sev_by_cve.get(cve_id)
                    and fact.get("score")
                    and cve_id not in customer_score_by_cve
                ):
                    customer_score_by_cve[cve_id] = str(fact["score"])

        cve_rows = []
        for cve_id in cve_ids:
            nvd_entry = nvd_by_id.get(cve_id, {})
            imgs = cve_to_images.get(cve_id, [])

            # Package/resource metadata: ticket attachment (Excel/JSON/HTML) is the
            # deterministic source of truth for the primary package name. NVD/Alpine
            # is used only when the attachment gave no package name, and to backfill
            # version fields the attachment left blank.
            nvd_pkgs: list[dict] = _dedup_packages(nvd_entry.get("packages") or [])
            attachment_pkgs = [p for p in (ticket_pkgs.get(cve_id) or []) if p.get("product")]
            attachment_primary = _pick_best_nvd_package(attachment_pkgs)
            if attachment_primary:
                primary = dict(attachment_primary)
                nvd_match = next(
                    (p for p in nvd_pkgs if (p.get("product") or "").lower() == primary["product"].lower()),
                    None,
                )
                if not primary.get("version_start") and nvd_match and nvd_match.get("version_start"):
                    primary["version_start"] = nvd_match["version_start"]
                if not primary.get("fixed_version") and nvd_match and nvd_match.get("fixed_version"):
                    primary["fixed_version"] = nvd_match["fixed_version"]
            elif nvd_pkgs:
                primary = _pick_best_nvd_package(nvd_pkgs)
            else:
                primary = None
            affected_resource = canonical_single_package_name(primary.get("product") if primary else None)
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
            )

            severity = nvd_entry.get("severity") or customer_sev_by_cve.get(cve_id)
            score = nvd_entry.get("score") or customer_score_by_cve.get(cve_id)

            cve_rows.append(
                {
                    "cve_id": cve_id,
                    "ghsa_id": cve_id if is_ghsa_id(cve_id) else nvd_entry.get("ghsa_id"),
                    "severity": severity,
                    "score": score,
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
                        {
                            f["source"]
                            for p in parsed_attachments
                            for f in p.get("cve_image_facts", [])
                            if f.get("cve_id") == cve_id and f.get("source")
                        }
                    ),
                }
            )

        aqua_processing_on = get_aqua_processing_enabled()
        if aqua_processing_on and (settings.aqua_api_key or "").strip():
            _set_run_status(run_id, "enriching_aqua")
            with db_session() as db:
                aqua = AquaClient()
                try:
                    for row in cve_rows:
                        cve_id = row.get("cve_id") or ""
                        nvd_entry = nvd_by_id.get(cve_id, {})
                        customer_name: str | None = None
                        ticket_for_cve = ticket_pkgs.get(cve_id) or []
                        if ticket_for_cve:
                            customer_name = (ticket_for_cve[0].get("product") or "").strip() or None
                        nvd_pkgs = row.get("all_packages") or []
                        nvd_name = None
                        if nvd_pkgs and isinstance(nvd_pkgs[0], dict):
                            nvd_name = (nvd_pkgs[0].get("product") or "").strip() or None
                        search_name = canonical_single_package_name(row.get("affected_resource")) or ""
                        if not search_name:
                            continue

                        basenames = image_basenames_for_cve_row(row)
                        if not basenames:
                            continue

                        aqua_search = resolve_aqua_search_name(nvd_pkgs, search_name)

                        by_image: dict[str, Any] = {}
                        pkg_by_image: dict[str, Any] = {}
                        row_ok = True
                        row_checked = False
                        primary_bn = basenames[0]
                        primary_result = None

                        for bn in basenames:
                            tag = settings.aqua_default_image_tag
                            for img in row.get("affected_images") or []:
                                if _image_path_basename(str(img.get("image") or "")).lower() == bn.lower():
                                    t = (img.get("tag") or "").strip()
                                    if t:
                                        tag = t
                                    break

                            result = cross_check_package(
                                db,
                                bn,
                                aqua_search,
                                tag=tag,
                                customer_name=customer_name,
                                nvd_name=nvd_name,
                                nvd_packages=nvd_pkgs,
                                client=aqua,
                            )
                            # Legacy shape (backward compat)
                            by_image[bn] = {
                                "found": result.found,
                                "aqua_package_name": result.aqua_package_name,
                                "aqua_package_version": result.aqua_package_version,
                                "candidates": candidates_to_json(result.candidates),
                                "aqua_checked": result.aqua_checked,
                            }
                            # New per-image shape that includes affected_resource
                            pkg_by_image[bn] = {
                                "affected_resource": search_name,
                                "aqua_pkg_found": result.found if result.aqua_checked else None,
                                "aqua_package_name": result.aqua_package_name,
                                "aqua_package_version": result.aqua_package_version,
                                "aqua_candidates": candidates_to_json(result.candidates),
                                "aqua_checked": result.aqua_checked,
                                "aqua_tag_requested": result.aqua_tag_requested,
                                "aqua_tag_used": result.aqua_tag_used,
                            }
                            if result.aqua_checked:
                                row_checked = True
                                if not result.found:
                                    row_ok = False
                            if bn == primary_bn:
                                primary_result = result

                        if by_image:
                            row["aqua_pkg_by_image"] = by_image
                            row["package_by_image"] = pkg_by_image
                        if row_checked:
                            row["aqua_pkg_found"] = row_ok
                            if primary_result:
                                row["aqua_package_name"] = primary_result.aqua_package_name
                                # Row-level affected_resource is NOT overwritten per-image;
                                # the canonical name lives in package_by_image[bn].aqua_package_name.
                                if not primary_result.found:
                                    row["aqua_candidates"] = candidates_to_json(
                                        primary_result.candidates
                                    )
                finally:
                    aqua.close()
        _set_run_status(run_id, "building_results")

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

        result = {
            "issue_key": issue.key,
            "sla_anchor_issue_key": issue.key,
            "sla_anchor_created": anchor.isoformat() if anchor else None,
            "organizations": org_names,
            "cves": cve_ids,
            "cve_rows": cve_rows,
            "nvd": enriched,
            # Findings provenance: structured attachment facts only.
            "cve_sources": [
                {"cve_id": f["cve_id"], "source": f["source"]}
                for p in parsed_attachments
                for f in p.get("cve_image_facts", [])
                if f.get("cve_id")
            ],
            # Mentions scraped from description (not included in findings / cve_ids).
            "description_cves": [{"cve_id": c.cve_id, "source": c.source} for c in desc_cves],
            "attachments": parsed_attachments,
            "images": images,
            "sheet_selection": (
                {aid: sorted(names) for aid, names in selection_map.items()} if selection_map else None
            ),
            "_plat_link_counts": {
                "links_checked": 0,
                "links_created": 0,
                "orgs_merged": 0,
                "errors": [],
            },
            "_aqua_processing_enabled": aqua_processing_on,
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
    """Relates-link plat_key to PLATFORM and append Organization from the parent."""
    link_plat_key_to_parent(jira, plat_key, source_issue_key, seen, counts)


def _link_plat_rows(
    jira: JiraClient,
    cve_rows: list[dict[str, Any]],
    source_issue_key: str,
    *,
    seen: set[str] | None = None,
    progress: _SyncProgressReporter | None = None,
) -> dict[str, Any]:
    """
    Link PLAT tickets to source_issue_key for each extracted CVE+image basename
    (same logic as Create PLAT API: find_plat_*_for_image), and append Organization
    from the PLATFORM parent onto each discovered PLAT.
    Returns counts: links_checked, links_created, orgs_merged, errors.
    """
    counts: dict[str, Any] = {
        "links_checked": 0,
        "links_created": 0,
        "orgs_merged": 0,
        "errors": [],
    }
    if seen is None:
        seen = set()
    for row in cve_rows:
        for pk in plat_keys_to_link_for_row(jira, row):
            _do_link(jira, pk, source_issue_key, seen, counts)
            if progress:
                progress.bump()
    return counts


@celery_app.task(name="link_plat_for_run")
def link_plat_for_run(run_id: str) -> dict[str, Any]:
    """Relates-link existing PLAT tickets to the PLATFORM parent and append Organization."""
    rid = uuid.UUID(run_id)
    _set_run_status(run_id, "linking_plat")
    try:
        with db_session() as db:
            run = db.get(ProcessingRun, rid)
            if not run or not run.result_json:
                raise ValueError("run has no stored result")
            result = json.loads(run.result_json)
            source_issue_key: str = (run.issue_key or "").strip()
        cve_rows: list[dict[str, Any]] = result.get("cve_rows") or []

        _init_plat_sync_log(run_id)

        if not cve_rows:
            _append_plat_sync_log(run_id, "info", "Link PLAT: no CVE rows in run, nothing to do")
            with db_session() as db:
                run = db.get(ProcessingRun, rid)
                if run:
                    run.status = "done"
                    db.add(run)
                    db.commit()
            return {
                "links_checked": 0,
                "links_created": 0,
                "orgs_merged": 0,
                "errors": [],
            }

        _append_plat_sync_log(
            run_id,
            "info",
            f"Link PLAT started for {source_issue_key or run_id} ({len(cve_rows)} CVE row(s))",
        )

        jira = JiraClient()
        try:
            # Phase 1: discover all unique PLAT keys (JQL searches; results cached in jira instance).
            progress = _SyncProgressReporter(run_id)
            progress.set_phase("Discovering PLAT tickets", len(cve_rows), 1)
            all_plat_keys: list[str] = []
            seen_keys: set[str] = set()
            for row in cve_rows:
                for pk in plat_keys_to_link_for_row(jira, row):
                    norm = pk.strip().upper()
                    if norm and norm not in seen_keys:
                        seen_keys.add(norm)
                        all_plat_keys.append(pk.strip())
                progress.bump()

            _append_plat_sync_log(
                run_id,
                "info",
                f"Discovered {len(all_plat_keys)} unique PLAT ticket(s) across {len(cve_rows)} CVE row(s)",
            )

            # Phase 2: link and merge Organization for each discovered PLAT key.
            # Keys were already deduplicated in phase 1; no JQL re-runs needed.
            progress.set_phase("Linking and merging Organization", max(len(all_plat_keys), 1), 2)
            link_counts: dict[str, Any] = {
                "links_checked": 0,
                "links_created": 0,
                "orgs_merged": 0,
                "errors": [],
            }
            link_seen: set[str] = set()
            for pk in all_plat_keys:
                _do_link(jira, pk, source_issue_key, link_seen, link_counts)
                progress.bump()

            errors = link_counts.get("errors") or []
            summary = (
                f"Link PLAT finished: {link_counts['links_checked']} checked, "
                f"{link_counts['links_created']} linked, "
                f"{link_counts['orgs_merged']} org(s) merged, "
                f"{len(errors)} error(s)"
            )
            _append_plat_sync_log(run_id, "info", summary)
            for err in errors[:20]:
                _append_plat_sync_log(run_id, "warn", str(err))
        finally:
            jira.close()

        with db_session() as db:
            run = db.get(ProcessingRun, rid)
            if run:
                try:
                    merged = json.loads(run.result_json) if run.result_json else {}
                except json.JSONDecodeError:
                    merged = {}
                merged["_plat_link_counts"] = link_counts
                merged.pop("_plat_sync_progress", None)
                run.status = "done"
                run.result_json = json.dumps(merged)
                db.add(run)
                db.commit()
        return link_counts
    except Exception as e:
        import traceback
        err_msg = str(e)
        tb_str = traceback.format_exc()
        _append_plat_sync_log(run_id, "error", f"Link PLAT failed: {err_msg}")
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
                res.pop("_plat_sync_progress", None)
                run.result_json = json.dumps(res)
                db.add(run)
                db.commit()
        raise


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
        _init_plat_sync_log(run_id)
        if not cve_rows:
            _append_plat_sync_log(run_id, "info", "Sync finished: no CVE rows in run")
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
            "packages_checked": 0,
            "packages_updated": 0,
            "package_names_rewritten": 0,
        }
        try:
            # PLAT Sec-Vuln keys for this PLATFORM ticket only (per CVE × affected image).
            all_keys: set[str] = set()
            for row in cve_rows:
                all_keys |= plat_sec_keys_scoped_to_run(row)

            _append_plat_sync_log(
                run_id,
                "info",
                f"Sync started for {source_issue_key or run_id} "
                f"({len(cve_rows)} CVE row(s), {len(all_keys)} PLAT Security ticket(s))",
            )
            progress.set_phase("Reading PLAT fields from Jira", len(all_keys), 1)
            _append_plat_sync_log(
                run_id,
                "info",
                f"Phase 1: reading {len(all_keys)} PLAT Security ticket(s) from Jira",
            )

            for pk in sorted(all_keys):
                try:
                    m = jira.get_issue_platsync_fields(pk)
                    if m:
                        plat_meta[pk] = m
                        stats["fields_read"] += 1
                except Exception as ex:
                    err = f"{pk} read field error: {ex}"
                    sync_errors.append(err)
                    _append_plat_sync_log(run_id, "warn", err)
                progress.bump()

            _append_plat_sync_log(
                run_id,
                "info",
                f"Phase 1 done: {stats['fields_read']} ticket(s) read, {len(sync_errors)} error(s)",
            )

            # Update plat_security_field_sync mapping on each row with the retrieved values
            for row in cve_rows:
                row.pop("plat_app_fix_versions", None)
                row.pop("plat_tag_numbers", None)
                sync_map: dict[str, dict[str, str]] = {}
                for pk in plat_sec_keys_scoped_to_run(row):
                    m = plat_meta.get(pk)
                    if not m:
                        continue
                    def _sync_val(raw: object) -> str:
                        s = str(raw or "").strip()
                        return s if s else "None"

                    issue_status = _sync_val(m.get("issue_status"))
                    fix_versions = _sync_val(m.get("fix_versions"))
                    tag_numbers = _sync_val(m.get("tag_numbers"))
                    if plat_issue_status_is_invalid(issue_status):
                        fix_versions = "N/A"
                        tag_numbers = "N/A"
                    sync_map[pk] = {
                        "fix_versions": fix_versions,
                        "tag_numbers": tag_numbers,
                        "issue_status": issue_status,
                        "package_name": _sync_val(m.get("package_name")),
                        "package_vuln_version": _sync_val(m.get("package_vuln_version")),
                        "vendor_fix_version": _sync_val(m.get("vendor_fix_version")),
                    }
                if sync_map:
                    row["plat_security_field_sync"] = sync_map
                    apply_plat_vendor_fields_from_sync(row)
                else:
                    row.pop("plat_security_field_sync", None)

        finally:
            jira.close()

        # Optional rewrite of wrong historical Package Name on PLAT CVE tickets in Jira.
        if get_aqua_processing_enabled() and get_rewrite_plat_package_name_on_sync():
            _set_run_status(run_id, "syncing_plat_rewrite")
            _append_plat_sync_log(
                run_id,
                "info",
                "Phase 2: preparing package names from Aqua cache",
            )
            rows_prepared = 0
            with db_session() as db:
                aqua = AquaClient()
                try:
                    for row in cve_rows:
                        nvd_pkgs = row.get("all_packages") or []
                        search_name = canonical_single_package_name(row.get("affected_resource")) or ""
                        if not search_name and nvd_pkgs and isinstance(nvd_pkgs[0], dict):
                            search_name = (nvd_pkgs[0].get("product") or "").strip()
                        basenames = image_basenames_for_cve_row(row)
                        if not basenames:
                            continue
                        if not search_name and not nvd_pkgs:
                            continue
                        aqua_search = resolve_aqua_search_name(nvd_pkgs, search_name)
                        nvd_name: str | None = None
                        if nvd_pkgs and isinstance(nvd_pkgs[0], dict):
                            nvd_name = (nvd_pkgs[0].get("product") or "").strip() or None
                        by_image: dict[str, Any] = dict(row.get("aqua_pkg_by_image") or {})
                        pkg_by_image: dict[str, Any] = dict(row.get("package_by_image") or {})
                        row_ok = True
                        row_checked = False
                        primary_bn = basenames[0]
                        primary_result = None
                        for bn in basenames:
                            tag = get_aqua_default_image_tag()
                            for img in row.get("affected_images") or []:
                                if _image_path_basename(str(img.get("image") or "")).lower() == bn.lower():
                                    t = (img.get("tag") or "").strip()
                                    if t:
                                        tag = t
                                    break
                            result_ck = cross_check_package(
                                db,
                                bn,
                                aqua_search,
                                tag=tag,
                                nvd_name=nvd_name,
                                nvd_packages=nvd_pkgs,
                                force_refresh=False,
                                client=aqua,
                            )
                            by_image[bn] = {
                                "found": result_ck.found,
                                "aqua_package_name": result_ck.aqua_package_name,
                                "aqua_package_version": result_ck.aqua_package_version,
                                "candidates": candidates_to_json(result_ck.candidates),
                                "aqua_checked": result_ck.aqua_checked,
                            }
                            pkg_by_image[bn] = {
                                "affected_resource": search_name,
                                "aqua_pkg_found": result_ck.found if result_ck.aqua_checked else None,
                                "aqua_package_name": result_ck.aqua_package_name,
                                "aqua_package_version": result_ck.aqua_package_version,
                                "aqua_candidates": candidates_to_json(result_ck.candidates),
                                "aqua_checked": result_ck.aqua_checked,
                                "aqua_tag_requested": result_ck.aqua_tag_requested,
                                "aqua_tag_used": result_ck.aqua_tag_used,
                            }
                            if result_ck.aqua_checked:
                                row_checked = True
                                if not result_ck.found:
                                    row_ok = False
                            if bn == primary_bn:
                                primary_result = result_ck
                        if by_image:
                            row["aqua_pkg_by_image"] = by_image
                            row["package_by_image"] = pkg_by_image
                        if row_checked:
                            row["aqua_pkg_found"] = row_ok
                            if primary_result:
                                row["aqua_package_name"] = primary_result.aqua_package_name
                                if not primary_result.found:
                                    row["aqua_candidates"] = candidates_to_json(primary_result.candidates)
                                else:
                                    row.pop("aqua_candidates", None)
                            rows_prepared += 1
                finally:
                    aqua.close()
            stats["package_names_rewritten"] = rows_prepared
            _append_plat_sync_log(
                run_id,
                "info",
                f"Phase 2: {rows_prepared} CVE row(s) prepared; updating Package Name in Jira",
            )

            jira_pkg = JiraClient()
            try:
                for row in cve_rows:
                    for bn, pk in iter_plat_security_package_targets(row):
                        pkg = plat_jira_package_name_for_row(row, bn)
                        if not pkg:
                            continue
                        stats["packages_checked"] += 1
                        try:
                            wr = jira_pkg.update_plat_security_package_name(pk, pkg)
                            if wr.package_name_updated:
                                stats["packages_updated"] += 1
                        except Exception as ex:
                            err = f"{pk} package rewrite: {ex}"
                            sync_errors.append(err)
                            _append_plat_sync_log(run_id, "warn", err)
            finally:
                jira_pkg.close()
            _append_plat_sync_log(
                run_id,
                "info",
                f"Phase 2 done: {stats['packages_checked']} checked, "
                f"{stats['packages_updated']} updated in Jira",
            )
        else:
            _append_plat_sync_log(run_id, "info", "Phase 2 skipped (rewrite Package Name on sync is off)")

        if sync_errors:
            result["_plat_sync_errors"] = sync_errors
        else:
            result.pop("_plat_sync_errors", None)
        result.pop("_plat_sync_progress", None)
        result["_plat_sync_stats"] = stats
        result["cve_rows"] = cve_rows
        summary = (
            f"Sync finished: {stats['fields_read']} field read(s)"
            + (
                f", {stats['packages_updated']} package name(s) updated"
                if get_rewrite_plat_package_name_on_sync()
                else ""
            )
            + (f", {len(sync_errors)} warning(s)" if sync_errors else "")
        )
        _append_plat_sync_log(run_id, "info", summary)
        with db_session() as db:
            run = db.get(ProcessingRun, rid)
            if run:
                try:
                    merged = json.loads(run.result_json) if run.result_json else {}
                except json.JSONDecodeError:
                    merged = {}
                merged.update(result)
                # Progress is written only to DB during sync; drop stale copy from merged.
                merged.pop("_plat_sync_progress", None)
                run.status = "done"
                run.result_json = json.dumps(merged)
                db.add(run)
                db.commit()
        return result
    except Exception as e:
        import traceback
        err_msg = str(e)
        tb_str = traceback.format_exc()
        _append_plat_sync_log(run_id, "error", f"Sync failed: {err_msg}")
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
                res.pop("_plat_sync_progress", None)
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

        sync_plat_for_run.apply_async(args=[str(run.id)], queue="plat_sync")
        with db_session() as db:
            row = db.get(IssueSyncSchedule, issue_key)
            if row:
                row.last_auto_sync_at = now
                db.add(row)
                db.commit()
        enqueued.append(issue_key)

    return {"enqueued": enqueued, "skipped": skipped, "checked_at": now.isoformat()}

