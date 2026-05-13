from __future__ import annotations

import json
import re
from typing import Any

from api.app.config import settings
from api.app.db import db_session
from api.app.jira_client import JiraClient, PlatTicket
from api.app.models import CveCache, CustomerSla, ProcessingRun
from api.app.sla_commitment import due_date_from_anchor
from api.app.nvd_client import NvdClient, _extract_affected_packages
from api.app.parsing import extract_cves, extract_images, normalize_description, parse_attachment_bytes
from worker.app.celery_app import celery_app


def _set_run_status(run_id: str, status: str) -> None:
    with db_session() as db:
        run = db.get(ProcessingRun, run_id)
        if run:
            run.status = status
            db.add(run)
            db.commit()


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
        parsed_attachments = []
        for a, blob in blobs:
            parsed = parse_attachment_bytes(
                attachment_id=str(a["id"]),
                filename=str(a["filename"]),
                mime_type=a.get("mimeType"),
                data=blob,
            )
            parsed_attachments.append(
                {
                    "id": parsed.attachment_id,
                    "filename": parsed.filename,
                    "mimeType": parsed.mime_type,
                    "status": parsed.status,
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
                        # Re-parse packages from cached raw_json (no schema change needed).
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

        # Look up associated PLAT tickets (Security Vulnerability + Bug) for each CVE.
        _set_run_status(run_id, "looking_up_plat_tickets")
        cve_to_plat: dict[str, list[dict]] = {}
        cve_to_plat_security_by_image: dict[str, dict[str, list[str]]] = {}
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
                except Exception:
                    cve_to_plat[cve_id] = []
                    cve_to_plat_security_by_image[cve_id] = {}
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

        # Build PlainID image filter from configurable token list.
        _plainid_tokens = tuple(
            t.strip().lower()
            for t in settings.plainid_image_patterns.split(",")
            if t.strip()
        )
        # Always accept images whose path starts with "plainid/".
        _plainid_tokens = _plainid_tokens + ("plainid",)

        def _is_plainid_image(image_name: str) -> bool:
            lower = image_name.lower()
            return any(tok in lower for tok in _plainid_tokens)

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

        # 2. Legacy: free-text images from description apply to all CVEs in description.
        desc_cve_ids = {c.cve_id for c in desc_cves}
        for i in desc_images:
            if not _is_plainid_image(i.image):
                continue
            for cve_id in desc_cve_ids:
                if cve_id not in cve_to_images:
                    continue
                key = (cve_id, i.image, i.tag)
                if key not in seen_img_keys:
                    seen_img_keys.add(key)
                    cve_to_images[cve_id].append({"image": i.image, "tag": i.tag, "source": i.source})

        # 3. Legacy: free-text images from attachments (when no structured facts were extracted).
        #    Correlate by CVEs found in the same attachment.
        for p in parsed_attachments:
            if p.get("cve_image_facts"):
                continue  # structured extraction succeeded — skip legacy correlation
            att_cves = {c["cve_id"] for c in p["cves"]}
            for img_dict in p.get("images", []):
                if not _is_plainid_image(img_dict["image"]):
                    continue
                for cve_id in att_cves:
                    if cve_id not in cve_to_images:
                        continue
                    key = (cve_id, img_dict["image"], img_dict["tag"])
                    if key not in seen_img_keys:
                        seen_img_keys.add(key)
                        cve_to_images[cve_id].append(img_dict)

        # Build a map of CVE -> list of package records from Excel attachments.
        cve_to_excel_pkgs: dict[str, list[dict]] = {}
        for p in parsed_attachments:
            for ep in p.get("packages", []):
                cve_to_excel_pkgs.setdefault(ep["cve_id"], []).append(ep)

        def _img_tokens(img_name: str) -> list[str]:
            """Return searchable substrings for an image name, e.g. 'plainid/pip-operator' → ['pip-operator','pip','operator']."""
            name = re.sub(r"^plainid/", "", img_name, flags=re.IGNORECASE).lower()
            parts = re.split(r"[-_]", name)
            return [name] + parts

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

        _set_run_status(run_id, "building_results")

        cve_rows = []
        for cve_id in cve_ids:
            nvd_entry = nvd_by_id.get(cve_id, {})
            imgs = cve_to_images.get(cve_id, [])

            # Excel package data takes priority over NVD CPE (it reflects the actual installed version).
            excel_pkgs = cve_to_excel_pkgs.get(cve_id, [])
            if excel_pkgs:
                # Deduplicate by package name, keep first occurrence per package.
                seen_names: set[str] = set()
                deduped_excel: list[dict] = []
                for ep in excel_pkgs:
                    if ep["package_name"] not in seen_names:
                        seen_names.add(ep["package_name"])
                        deduped_excel.append(ep)
                first_ep = deduped_excel[0]
                affected_resource = first_ep["package_name"]
                affected_version = first_ep["package_version"]
                fixed_version = first_ep["fixed_version"]
                # Store as all_packages for the comment builder.
                all_packages = [
                    {
                        "vendor": "",
                        "product": ep["package_name"],
                        "version_start": ep["package_version"],
                        "fixed_version": ep["fixed_version"],
                    }
                    for ep in deduped_excel
                ]
            else:
                # Fall back to NVD CPE data.
                nvd_pkgs: list[dict] = _dedup_packages(nvd_entry.get("packages") or [])
                first_np = nvd_pkgs[0] if nvd_pkgs else None
                affected_resource = first_np["product"] if first_np else None
                affected_version = first_np["version_start"] if first_np else None
                fixed_version = first_np["fixed_version"] if first_np else None
                all_packages = nvd_pkgs

            raw_plat = cve_to_plat.get(cve_id, [])
            plat_security_keys = [
                t["key"] for t in raw_plat if t["issue_type"] == "Security Vulnerability"
            ]
            plat_security_for_images = dict(cve_to_plat_security_by_image.get(cve_id, {}))

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
                    "plat_tickets":  _filter_plat_tickets(raw_plat, imgs),
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

        result = {
            "issue_key": issue.key,
            "sla_anchor_issue_key": issue.key,
            "sla_anchor_created": anchor.isoformat() if anchor else None,
            "cves": cve_ids,
            "cve_rows": cve_rows,
            "nvd": enriched,
            "cve_sources": [{"cve_id": c.cve_id, "source": c.source} for c in desc_cves]
            + [c for p in parsed_attachments for c in p["cves"]],
            "attachments": parsed_attachments,
            "images": images,
        }
    except Exception as e:
        _set_run_status(run_id, f"failed: {type(e).__name__}")
        raise

    with db_session() as db:
        run = db.get(ProcessingRun, run_id)
        if run:
            run.status = "done"
            run.result_json = json.dumps(result)
            db.add(run)
            db.commit()

    return result

