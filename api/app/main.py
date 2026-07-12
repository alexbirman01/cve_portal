import importlib.metadata
import json
import os
import sys
import uuid
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import func, text

from api.app.config import settings
from api.app.package_name import canonical_single_package_name
from api.app.cve_row_derived import (
    _image_path_basename,
    cve_rows_from_result,
    derive_cve_state,
    derive_ticket_remediation_status,
    image_basenames_for_cve_row,
    plat_keys_aggregate_from_rows,
)
from api.app.aqua_packages import candidates_to_json, cross_check_package, resolve_aqua_search_name
from api.app.jira_client import JiraClient, PlatSearchError
from api.app.plat_audit import log_plat_audit
from api.app.plat_linking import filter_plat_hits_for_image
from api.app.db import engine, db_session
from api.app.allowed_images import normalize_image_basename
from api.app.aqua_catalog import (
    AquaPackagesRefreshIn,
    AquaPackagesSettingsIn,
    delete_aqua_cache_entry,
    get_aqua_package_entry,
    get_aqua_packages_settings,
    list_aqua_package_catalog,
    patch_aqua_packages_settings,
    refresh_aqua_cache_entry,
)
from api.app.models import AllowedImage, Base, CustomerSla, IssueSyncSchedule, ProcessingRun
from api.app.sla_commitment import due_date_from_anchor, parse_jira_created
from api.app.parsing import normalize_description
from worker.app.tasks import process_issue, sync_plat_for_run


app = FastAPI(title="CVE Portal API", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    Base.metadata.create_all(bind=engine)
    # Add aliases column if upgrading from a schema that predates it.
    with engine.connect() as conn:
        conn.execute(
            text(
                "ALTER TABLE allowed_images ADD COLUMN IF NOT EXISTS "
                "aliases VARCHAR(1024) NOT NULL DEFAULT ''"
            )
        )
        conn.commit()


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/config/client")
def client_config():
    """Non-secret values for the browser (e.g. Jira links)."""
    base = (settings.jira_base_url or "").strip().rstrip("/")
    return {"jira_browse_url": f"{base}/browse" if base else ""}


@app.get("/api/issues/{issue_key}")
def get_issue(issue_key: str):
    jira = JiraClient()
    try:
        issue = jira.get_issue(issue_key)
        return {
            "key": issue.key,
            "summary": issue.summary,
            "issuetype": issue.issuetype,
            "project": issue.project,
            "reporter": issue.reporter,
            "organizations": issue.organizations,
            "organization_refs": issue.organization_refs,
            "description_raw": issue.description_raw,
            "description_text": normalize_description(issue.description_raw),
            "attachments": issue.attachments,
            "created": issue.created.isoformat() if issue.created else None,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    finally:
        jira.close()


class CommentIn(BaseModel):
    body: str
    internal: bool = True


def _jira_priority_name(severity: str | None) -> str | None:
    """Default High when unknown; map NVD-style severity to Jira priority names."""
    if not severity:
        return "High"
    u = severity.upper()
    if u in ("CRITICAL", "HIGH"):
        return "High"
    if u == "MEDIUM":
        return "Medium"
    if u == "LOW":
        return "Low"
    return "High"


class OrgRefIn(BaseModel):
    id: str | None = None
    name: str | None = None


class CreatePlatIn(BaseModel):
    cve_id: str
    image_basename: str
    package_name: str
    package_version: str
    severity: str | None = None
    organizations: list[OrgRefIn] | None = None
    # When organizations is empty, server copies org IDs from this issue (portal parent ticket).
    source_issue_key: str | None = None
    # Bug create only: description / display lines (optional; server falls back).
    image_display: str | None = None
    resource_label: str | None = None
    vendor_fix_version: str | None = None
    # ISO YYYY-MM-DD from portal SLA row; sets Jira system field duedate when valid.
    sla_due_date: str | None = None
    # If provided, the newly created/found key is persisted into this run's result_json.
    run_id: str | None = None

    @field_validator("organizations", mode="before")
    @classmethod
    def _normalize_organizations(cls, v: object) -> object:
        if v is None:
            return None
        if not isinstance(v, list):
            return v
        out: list[dict[str, str]] = []
        for item in v:
            if isinstance(item, str):
                s = item.strip()
                if s:
                    out.append({"name": s})
            elif isinstance(item, dict):
                d: dict[str, str] = {}
                if item.get("id") is not None and str(item["id"]).strip():
                    d["id"] = str(item["id"]).strip()
                if item.get("name") is not None and str(item["name"]).strip():
                    d["name"] = str(item["name"]).strip()
                if d:
                    out.append(d)
        return out


def _persist_plat_key_into_run(
    run_id: str | None,
    cve_id: str,
    key: str,
    issue_type: str,
    *,
    image_basename: str | None = None,
    summary: str | None = None,
) -> None:
    """Write a newly created/found PLAT key back into the run's result_json so the UI stays consistent after remount."""
    if not run_id or not key:
        return
    try:
        rid = uuid.UUID(run_id)
    except ValueError:
        return
    img = (image_basename or "").strip()
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run or not run.result_json:
            return
        data = json.loads(run.result_json)
        for row in data.get("cve_rows") or []:
            if row.get("cve_id") != cve_id:
                continue
            tickets: list[dict] = list(row.get("plat_tickets") or [])
            existing = next((t for t in tickets if t.get("key") == key), None)
            if existing is None:
                tickets.append({"key": key, "issue_type": issue_type})
            if img:
                by_img: dict[str, list[str]] = dict(row.get("plat_security_for_images") or {})
                cur = set(by_img.get(img) or [])
                cur.add(key)
                by_img[img] = sorted(cur)
                row["plat_security_for_images"] = by_img
            sec_keys: set[str] = set(row.get("plat_security_keys") or [])
            sec_keys.add(key)
            row["plat_security_keys"] = sorted(sec_keys)
            row["plat_tickets"] = tickets
            break
        run.result_json = json.dumps(data)
        db.add(run)
        db.commit()


def _link_plat_keys_to_parent(
    jira: "JiraClient",
    plat_keys: list[str],
    source_issue_key: str | None,
) -> list[str]:
    """Link each PLAT key to the source PLATFORM issue; return any non-fatal warnings."""
    warnings: list[str] = []
    if not source_issue_key or not plat_keys:
        return warnings
    for plat_key in plat_keys:
        result = jira.ensure_plat_linked_to_parent(plat_key, source_issue_key)
        if result.error_warning:
            warnings.append(result.error_warning)
    return warnings


def _aqua_blocks_plat_create(run_id: str | None, cve_id: str, image_basename: str) -> str | None:
    """Return error detail if Aqua is configured and package is not confirmed for this image."""
    if not (settings.aqua_api_key or "").strip():
        return None
    if not run_id:
        return None
    try:
        rid = uuid.UUID(run_id)
    except ValueError:
        return None
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run or not run.result_json:
            return None
        data = json.loads(run.result_json)
        for row in data.get("cve_rows") or []:
            if row.get("cve_id") != cve_id:
                continue
            fold = image_basename.lower()

            def _lookup_entry(mapping: dict, found_key: str = "found") -> dict | None:
                e = mapping.get(image_basename)
                if e is None:
                    for k, v in mapping.items():
                        if str(k).lower() == fold:
                            e = v
                            break
                return e

            # Prefer new package_by_image (uses aqua_pkg_found key)
            pbi = row.get("package_by_image") or {}
            if pbi:
                entry = _lookup_entry(pbi)
                if entry is not None:
                    if entry.get("aqua_checked") and entry.get("aqua_pkg_found") is False:
                        return (
                            "Package name not confirmed in Aqua for this image. "
                            "Edit the package name and re-check, or pick a suggestion."
                        )
                    return None

            # Fallback to legacy aqua_pkg_by_image (uses found key)
            by_img = row.get("aqua_pkg_by_image") or {}
            if by_img:
                entry = _lookup_entry(by_img)
                if entry is not None:
                    if entry.get("aqua_checked") and entry.get("found") is False:
                        return (
                            "Package name not confirmed in Aqua for this image. "
                            "Edit the package name and re-check, or pick a suggestion."
                        )
                    return None

            if row.get("aqua_pkg_found") is False:
                return (
                    "Package name not confirmed in Aqua. "
                    "Edit the package name and re-check, or pick a suggestion."
                )
            return None
    return None


def _plat_create_audit_base(
    *,
    cve_id: str,
    image: str,
    source_issue_key: str | None,
    run_id: str | None,
    check: str,
    search_results: list[dict[str, str]],
) -> dict[str, object]:
    hits = filter_plat_hits_for_image(search_results, image)
    return {
        "check": check,
        "cve_id": cve_id,
        "image": image,
        "source_issue": (source_issue_key or "").strip(),
        "run_id": (run_id or "").strip(),
        "search_hits": hits,
        "search_count": len(search_results),
    }


def _plat_create_resolve_search(
    search_results: list[dict[str, str]],
    *,
    cve_id: str,
    image: str,
    source_issue_key: str | None,
    run_id: str | None,
    check: str,
    initial_image_hits: list[str] | None = None,
) -> list[str] | None:
    """
    Evaluate PLAT search for create/reuse.
    Returns reuse keys, None to proceed with create, or raises HTTPException.
    """
    audit = _plat_create_audit_base(
        cve_id=cve_id,
        image=image,
        source_issue_key=source_issue_key,
        run_id=run_id,
        check=check,
        search_results=search_results,
    )
    hits = audit["search_hits"]
    assert isinstance(hits, list)

    if check == "pre_create" and hits and initial_image_hits is not None and not initial_image_hits:
        audit["recovered_on_pre_create"] = True

    if len(hits) > 1:
        audit["decision"] = "blocked_multiple_matches"
        log_plat_audit("plat_create_audit", **audit)
        detail = f"Multiple PLAT tickets already exist for {cve_id} / {image}: {', '.join(hits)}"
        raise HTTPException(status_code=409, detail=detail)

    if len(hits) == 1:
        audit["decision"] = "reused_existing"
        log_plat_audit("plat_create_audit", **audit)
        return hits

    audit["decision"] = "no_match"
    log_plat_audit("plat_create_audit", **audit)
    return None


def _plat_create_finish_reuse(
    jira: JiraClient,
    *,
    existing: list[str],
    payload: CreatePlatIn,
    image: str,
) -> dict:
    warnings = _link_plat_keys_to_parent(jira, existing, payload.source_issue_key)
    for k in existing:
        _persist_plat_key_into_run(
            payload.run_id,
            payload.cve_id.strip(),
            k,
            "Security Vulnerability",
            image_basename=image,
        )
    out: dict = {"exists": True, "keys": existing}
    if warnings:
        out["link_warnings"] = warnings
    return out


@app.post("/api/plat")
def create_plat_ticket(payload: CreatePlatIn):
    block = _aqua_blocks_plat_create(
        payload.run_id,
        payload.cve_id.strip(),
        payload.image_basename.strip(),
    )
    if block:
        raise HTTPException(status_code=400, detail=block)
    jira = JiraClient()
    cve_id = payload.cve_id.strip()
    image = payload.image_basename.strip()
    try:
        try:
            initial_results = jira.search_plat_security_for_cve(cve_id)
        except PlatSearchError as exc:
            log_plat_audit(
                "plat_create_audit",
                check="initial",
                cve_id=cve_id,
                image=image,
                source_issue=(payload.source_issue_key or "").strip(),
                run_id=(payload.run_id or "").strip(),
                decision="search_failed",
                error=str(exc),
            )
            raise HTTPException(
                status_code=503,
                detail=f"Cannot verify existing PLAT tickets in Jira: {exc}",
            ) from exc

        initial_image_hits = filter_plat_hits_for_image(initial_results, image)
        reuse = _plat_create_resolve_search(
            initial_results,
            cve_id=cve_id,
            image=image,
            source_issue_key=payload.source_issue_key,
            run_id=payload.run_id,
            check="initial",
        )
        if reuse:
            return _plat_create_finish_reuse(jira, existing=reuse, payload=payload, image=image)

        try:
            pre_results = jira.search_plat_security_for_cve(cve_id)
        except PlatSearchError as exc:
            log_plat_audit(
                "plat_create_audit",
                check="pre_create",
                cve_id=cve_id,
                image=image,
                source_issue=(payload.source_issue_key or "").strip(),
                run_id=(payload.run_id or "").strip(),
                decision="search_failed",
                error=str(exc),
            )
            raise HTTPException(
                status_code=503,
                detail=f"Cannot verify existing PLAT tickets in Jira before create: {exc}",
            ) from exc

        reuse = _plat_create_resolve_search(
            pre_results,
            cve_id=cve_id,
            image=image,
            source_issue_key=payload.source_issue_key,
            run_id=payload.run_id,
            check="pre_create",
            initial_image_hits=initial_image_hits,
        )
        if reuse:
            return _plat_create_finish_reuse(jira, existing=reuse, payload=payload, image=image)

        org_refs = [r.model_dump(exclude_none=True) for r in (payload.organizations or [])]
        key = jira.create_plat_security_vulnerability(
            cve_id,
            image,
            payload.package_name.strip(),
            payload.package_version.strip(),
            priority_name=_jira_priority_name(payload.severity),
            organization_refs=org_refs or None,
            source_issue_key=payload.source_issue_key,
            due_date=payload.sla_due_date,
        )
        if not key:
            raise HTTPException(status_code=502, detail="Jira did not return issue key")
        log_plat_audit(
            "plat_create_audit",
            check="pre_create",
            cve_id=cve_id,
            image=image,
            source_issue=(payload.source_issue_key or "").strip(),
            run_id=(payload.run_id or "").strip(),
            decision="created_new",
            created_key=key,
        )
        warnings = _link_plat_keys_to_parent(jira, [key], payload.source_issue_key)
        _persist_plat_key_into_run(
            payload.run_id,
            cve_id,
            key,
            "Security Vulnerability",
            image_basename=image,
        )
        out = {"exists": False, "key": key}
        if warnings:
            out["link_warnings"] = warnings
        return out
    except httpx.HTTPStatusError as e:
        detail = e.response.text if e.response is not None else str(e)
        raise HTTPException(status_code=400, detail=detail) from e
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    finally:
        jira.close()


@app.post("/api/issues/{issue_key}/comment")
def post_comment(issue_key: str, payload: CommentIn):
    jira = JiraClient()
    try:
        res = jira.add_comment(issue_key, payload.body, internal=payload.internal)
        return {"ok": True, "jira": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    finally:
        jira.close()


@app.put("/api/issues/{issue_key}/comment/status")
def upsert_customer_status_comment(issue_key: str, payload: CommentIn):
    """Create or update the single portal-managed customer status table comment."""
    jira = JiraClient()
    try:
        res = jira.upsert_customer_status_comment(
            issue_key, payload.body, internal=payload.internal
        )
        return {"ok": True, **res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    finally:
        jira.close()


@app.post("/api/issues/{issue_key}/process")
def start_processing(issue_key: str):
    jira = JiraClient()
    try:
        issue = jira.get_issue(issue_key)
        it = (issue.issuetype or "").strip().casefold()
        if it != "security":
            raise HTTPException(
                status_code=400,
                detail=(
                    f"This portal only processes Security tickets; "
                    f"got issuetype '{issue.issuetype or 'Unknown'}'."
                ),
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    finally:
        jira.close()

    run_id = uuid.uuid4()
    with db_session() as db:
        run = ProcessingRun(id=run_id, issue_key=issue_key, status="queued")
        db.add(run)
        db.commit()

    async_result = process_issue.delay(str(run_id), issue_key)
    with db_session() as db:
        run = db.get(ProcessingRun, run_id)
        if run:
            run.celery_task_id = async_result.id
            db.add(run)
            db.commit()

    return {"run_id": str(run_id), "task_id": async_result.id}


@app.get("/api/jobs")
def list_jobs(limit: int = 50):
    with db_session() as db:
        runs = (
            db.query(ProcessingRun)
            .order_by(ProcessingRun.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "run_id": str(r.id),
                "issue_key": r.issue_key,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "cve_count": len(json.loads(r.result_json).get("cves", [])) if r.result_json else None,
            }
            for r in runs
        ]


@app.get("/api/jobs/cve-status")
def list_jobs_cve_status(limit: int = 50):
    """Latest processing run per issue, with per-CVE derived state from that run."""

    def _parent_issue_and_project(res: dict | None, fallback_key: str) -> tuple[str, str]:
        parent = ""
        if isinstance(res, dict) and res.get("issue_key"):
            parent = str(res["issue_key"]).strip()
        if not parent:
            parent = (fallback_key or "").strip()
        proj = parent.split("-", 1)[0].strip().upper() if "-" in parent else parent.upper()
        return parent, proj

    cap = max(1, min(limit, 200))
    with db_session() as db:
        runs = (
            db.query(ProcessingRun)
            .order_by(ProcessingRun.created_at.desc())
            .limit(2000)
            .all()
        )
    seen: dict[str, object] = {}
    for r in runs:
        if r.issue_key in seen:
            continue
        seen[r.issue_key] = r
        if len(seen) >= cap:
            break

    chosen = sorted(
        seen.values(),
        key=lambda x: x.created_at or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )

    schedule_by_key: dict[str, IssueSyncSchedule] = {}
    with db_session() as db:
        issue_keys = [r.issue_key for r in chosen if r.issue_key]
        if issue_keys:
            folds = {k.casefold() for k in issue_keys}
            for row in db.query(IssueSyncSchedule).all():
                if row.issue_key.casefold() in folds:
                    schedule_by_key[row.issue_key.casefold()] = row

    out: list[dict] = []
    need_jira_orgs: list[str] = []
    for r in chosen:
        result = json.loads(r.result_json) if r.result_json else None
        rows = cve_rows_from_result(result if isinstance(result, dict) else None)
        rows_clean = [x for x in rows if isinstance(x, dict)]
        plat_keys = plat_keys_aggregate_from_rows(rows_clean)
        cves: list[dict] = []
        if rows and (r.status == "done" or r.status.startswith("failed")):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                cve_id = row.get("cve_id")
                if not cve_id:
                    continue
                cves.append(
                    {
                        "cve_id": str(cve_id),
                        "severity": row.get("severity"),
                        "cve_state": derive_cve_state(row, r.status),
                    }
                )
        cve_count = len(json.loads(r.result_json).get("cves", [])) if r.result_json else None
        needs_plat = sum(1 for c in cves if c.get("cve_state") == "needs_plat_cve")
        parent_issue_key, issue_project = _parent_issue_and_project(
            result if isinstance(result, dict) else None,
            r.issue_key,
        )
        if r.status.startswith("failed"):
            ticket_status = "failed"
        elif r.status != "done":
            ticket_status = "processing"
        elif needs_plat > 0:
            ticket_status = "in_progress"
        else:
            ticket_status = "done"
        remediation_status = derive_ticket_remediation_status(
            rows_clean,
            r.status,
            result if isinstance(result, dict) else None,
        )
        customer_names: list[str] = []
        if isinstance(result, dict):
            raw_orgs = result.get("organizations")
            if isinstance(raw_orgs, list):
                customer_names = [
                    str(x).strip() for x in raw_orgs if x and str(x).strip()
                ]
        if not customer_names and r.issue_key:
            need_jira_orgs.append(r.issue_key)
        sched = schedule_by_key.get(r.issue_key.casefold())
        out.append(
            {
                "issue_key": r.issue_key,
                "parent_issue_key": parent_issue_key,
                "issue_project": issue_project,
                "run_id": str(r.id),
                "run_status": r.status,
                "ticket_status": ticket_status,
                "remediation_status": remediation_status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                "cve_count": cve_count,
                "needs_plat_cve_count": needs_plat,
                "plat_keys": plat_keys,
                "customer_names": customer_names,
                "daily_sync_enabled": bool(sched.daily_sync_enabled) if sched else False,
                "last_auto_sync_at": (
                    sched.last_auto_sync_at.isoformat()
                    if sched and sched.last_auto_sync_at
                    else None
                ),
                "cves": cves,
            }
        )

    jira_orgs: dict[str, list[str]] = {}
    if need_jira_orgs:
        jira = JiraClient()
        try:
            for key in dict.fromkeys(need_jira_orgs):
                try:
                    issue = jira.get_issue(key)
                    jira_orgs[key] = list(issue.organizations or [])
                except Exception:
                    jira_orgs[key] = []
        finally:
            jira.close()
        for item in out:
            if not item.get("customer_names") and item.get("issue_key"):
                item["customer_names"] = jira_orgs.get(item["issue_key"], [])

    return out


@app.delete("/api/jobs/issue/{issue_key}")
def delete_processing_runs_for_issue(issue_key: str):
    """Delete all processing runs for this Jira issue from Postgres (removes portal history for the ticket)."""
    raw = (issue_key or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="issue_key required")
    fold = raw.casefold()
    with db_session() as db:
        n = (
            db.query(ProcessingRun)
            .filter(func.lower(ProcessingRun.issue_key) == fold)
            .delete(synchronize_session=False)
        )
        db.query(IssueSyncSchedule).filter(
            func.lower(IssueSyncSchedule.issue_key) == fold
        ).delete(synchronize_session=False)
        db.commit()
    return {"ok": True, "deleted_count": n}


class IssueSyncScheduleIn(BaseModel):
    daily_sync_enabled: bool


def _normalize_issue_key(raw: str) -> str:
    key = (raw or "").strip().upper()
    if not key:
        raise HTTPException(status_code=400, detail="issue_key required")
    return key


@app.patch("/api/issues/{issue_key}/sync-schedule")
def patch_issue_sync_schedule(issue_key: str, payload: IssueSyncScheduleIn):
    key = _normalize_issue_key(issue_key)
    with db_session() as db:
        row = db.get(IssueSyncSchedule, key)
        if not row:
            row = IssueSyncSchedule(issue_key=key, daily_sync_enabled=payload.daily_sync_enabled)
        else:
            row.daily_sync_enabled = payload.daily_sync_enabled
        db.add(row)
        db.commit()
        db.refresh(row)
        return {
            "issue_key": row.issue_key,
            "daily_sync_enabled": row.daily_sync_enabled,
            "last_auto_sync_at": (
                row.last_auto_sync_at.isoformat() if row.last_auto_sync_at else None
            ),
        }


def _pkg_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "n/a"


def _read_version_file() -> str:
    """Read VERSION file baked into the image, fallback to env, then 'dev'."""
    for path in ["/app/VERSION", os.path.join(os.path.dirname(__file__), "..", "..", "VERSION")]:
        try:
            with open(path) as f:
                v = f.read().strip()
                if v:
                    return v
        except OSError:
            pass
    return os.environ.get("APP_VERSION", "dev")


def _pg_host() -> str:
    """Extract host:port from the configured Postgres DSN."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(settings.postgres_dsn)
        host = parsed.hostname or ""
        port = parsed.port
        return f"{host}:{port}" if port else host
    except Exception:
        return ""


def _redis_host() -> str:
    """Extract host:port from the configured Redis URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(settings.redis_url)
        host = parsed.hostname or ""
        port = parsed.port
        return f"{host}:{port}" if port else host
    except Exception:
        return ""


def _probe_postgres() -> dict:
    from sqlalchemy import text
    host = _pg_host()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "host": host}
    except Exception as exc:
        return {"status": "error", "host": host, "detail": str(exc)[:200]}


def _probe_redis() -> dict:
    import redis as redis_lib
    host = _redis_host()
    try:
        r = redis_lib.Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        r.ping()
        return {"status": "ok", "host": host}
    except Exception as exc:
        return {"status": "error", "host": host, "detail": str(exc)[:200]}


def _probe_celery() -> dict:
    from worker.app.celery_app import celery_app as _celery
    try:
        resp = _celery.control.inspect(timeout=2).ping()
        if resp:
            workers = list(resp.keys())
            return {"status": "ok", "workers": workers}
        return {"status": "no_workers"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)[:200]}


@app.get("/api/about")
def about():
    """Return component versions, build info, and live health for the About dialog."""
    app_version = os.environ.get("APP_VERSION", "") or _read_version_file()
    git_commit = os.environ.get("GIT_COMMIT", "")
    return {
        "portal_version": app_version,
        "git_commit": git_commit,
        "python_version": sys.version.split()[0],
        "packages": {
            "fastapi": _pkg_version("fastapi"),
            "uvicorn": _pkg_version("uvicorn"),
            "pydantic": _pkg_version("pydantic"),
            "sqlalchemy": _pkg_version("sqlalchemy"),
            "celery": _pkg_version("celery"),
            "redis": _pkg_version("redis"),
            "httpx": _pkg_version("httpx"),
            "pdfplumber": _pkg_version("pdfplumber"),
        },
        "components": {
            "postgres": _probe_postgres(),
            "redis": _probe_redis(),
            "celery_worker": _probe_celery(),
        },
    }


class CustomerSlaCreateIn(BaseModel):
    customer_name: str
    sla_critical: str | None = None
    sla_high: str | None = None
    sla_medium: str | None = None
    sla_low: str | None = None

    @field_validator("customer_name", mode="before")
    @classmethod
    def _strip_name(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


class CustomerSlaUpdateIn(BaseModel):
    customer_name: str | None = None
    sla_critical: str | None = None
    sla_high: str | None = None
    sla_medium: str | None = None
    sla_low: str | None = None


def _sla_row_to_api(row: CustomerSla) -> dict:
    return {
        "id": str(row.id),
        "customer_name": row.customer_name,
        "sla_critical": row.sla_critical,
        "sla_high": row.sla_high,
        "sla_medium": row.sla_medium,
        "sla_low": row.sla_low,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@app.get("/api/sla/customers")
def list_customer_slas():
    with db_session() as db:
        rows = db.query(CustomerSla).order_by(CustomerSla.customer_name.asc()).all()
        return [_sla_row_to_api(r) for r in rows]


@app.post("/api/sla/customers", status_code=201)
def create_customer_sla(payload: CustomerSlaCreateIn):
    name = payload.customer_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="customer_name required")
    with db_session() as db:
        exists = db.query(CustomerSla).filter(CustomerSla.customer_name == name).first()
        if exists:
            raise HTTPException(status_code=409, detail="customer_name already exists")
        row = CustomerSla(
            customer_name=name,
            sla_critical=payload.sla_critical,
            sla_high=payload.sla_high,
            sla_medium=payload.sla_medium,
            sla_low=payload.sla_low,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return _sla_row_to_api(row)


@app.put("/api/sla/customers/{sla_id}")
def update_customer_sla(sla_id: str, payload: CustomerSlaUpdateIn):
    try:
        uid = uuid.UUID(sla_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid id") from e
    data = payload.model_dump(exclude_unset=True)
    with db_session() as db:
        row = db.get(CustomerSla, uid)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        if "customer_name" in data:
            new_name = (data["customer_name"] or "").strip()
            if not new_name:
                raise HTTPException(status_code=400, detail="customer_name cannot be empty")
            conflict = (
                db.query(CustomerSla)
                .filter(CustomerSla.customer_name == new_name, CustomerSla.id != uid)
                .first()
            )
            if conflict:
                raise HTTPException(status_code=409, detail="customer_name already exists")
            row.customer_name = new_name
        for key in ("sla_critical", "sla_high", "sla_medium", "sla_low"):
            if key in data:
                setattr(row, key, data[key])
        db.add(row)
        db.commit()
        db.refresh(row)
        return _sla_row_to_api(row)


@app.delete("/api/sla/customers/{sla_id}")
def delete_customer_sla(sla_id: str):
    try:
        uid = uuid.UUID(sla_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid id") from e
    with db_session() as db:
        row = db.get(CustomerSla, uid)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        db.delete(row)
        db.commit()
    return {"ok": True}


@app.get("/api/sla/due-date-preview")
def sla_due_date_preview(
    anchor: str = Query(..., description="ISO-8601 anchor datetime (e.g. Jira created)"),
    organizations: str = Query("", description="Comma-separated organization names"),
    severity: str = Query("HIGH"),
):
    dt_anchor = parse_jira_created(anchor)
    if not dt_anchor:
        raise HTTPException(status_code=400, detail="invalid anchor datetime")
    orgs = [o.strip() for o in organizations.split(",") if o.strip()]
    rows_by_customer_lower: dict[str, dict] = {}
    with db_session() as db:
        for r in db.query(CustomerSla).all():
            nm = (r.customer_name or "").strip()
            if not nm:
                continue
            rows_by_customer_lower[nm.casefold()] = {
                "sla_critical": r.sla_critical,
                "sla_high": r.sla_high,
                "sla_medium": r.sla_medium,
                "sla_low": r.sla_low,
            }
    due = due_date_from_anchor(dt_anchor, orgs, severity, rows_by_customer_lower)
    return {"due_date": due, "anchor": dt_anchor.isoformat(), "organizations": orgs, "severity": severity}


class AllowedImageCreateIn(BaseModel):
    name: str
    aliases: str = ""


class AllowedImageUpdateIn(BaseModel):
    name: str
    aliases: str = ""


def _allowed_image_to_api(row: AllowedImage) -> dict:
    return {
        "id": str(row.id),
        "name": row.name,
        "aliases": row.aliases or "",
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@app.get("/api/allowed-images")
def list_allowed_images():
    with db_session() as db:
        rows = db.query(AllowedImage).order_by(AllowedImage.name.asc()).all()
        return [_allowed_image_to_api(r) for r in rows]


@app.post("/api/allowed-images", status_code=201)
def create_allowed_image(payload: AllowedImageCreateIn):
    name = normalize_image_basename(payload.name)
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    with db_session() as db:
        exists = db.query(AllowedImage).filter(AllowedImage.name == name).first()
        if exists:
            raise HTTPException(status_code=409, detail="name already exists")
        row = AllowedImage(name=name, aliases=payload.aliases.strip())
        db.add(row)
        db.commit()
        db.refresh(row)
        return _allowed_image_to_api(row)


@app.put("/api/allowed-images/{image_id}")
def update_allowed_image(image_id: str, payload: AllowedImageUpdateIn):
    try:
        uid = uuid.UUID(image_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid id") from e
    name = normalize_image_basename(payload.name)
    if not name:
        raise HTTPException(status_code=400, detail="name cannot be empty")
    with db_session() as db:
        row = db.get(AllowedImage, uid)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        conflict = (
            db.query(AllowedImage)
            .filter(AllowedImage.name == name, AllowedImage.id != uid)
            .first()
        )
        if conflict:
            raise HTTPException(status_code=409, detail="name already exists")
        row.name = name
        row.aliases = payload.aliases.strip()
        db.add(row)
        db.commit()
        db.refresh(row)
        return _allowed_image_to_api(row)


@app.delete("/api/allowed-images/{image_id}")
def delete_allowed_image(image_id: str):
    try:
        uid = uuid.UUID(image_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid id") from e
    with db_session() as db:
        row = db.get(AllowedImage, uid)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        db.delete(row)
        db.commit()
    return {"ok": True}


_PLAT_SYNC_IN_PROGRESS = frozenset({"syncing_plat", "syncing_plat_rewrite", "syncing_aqua"})

# Celery pipeline statuses — PLAT sync requires a stored findings payload first.
_PIPELINE_ACTIVE = frozenset(
    {
        "queued",
        "fetching_issue",
        "extracting_from_description",
        "downloading_attachments",
        "parsing_attachments",
        "enriching_nvd",
        "enriching_rh",
        "enriching_cve5",
        "looking_up_plat_tickets",
        "building_results",
        "enriching_aqua",
    }
)


def _run_has_cve_rows(run: ProcessingRun) -> bool:
    if not run.result_json:
        return False
    try:
        data = json.loads(run.result_json)
    except json.JSONDecodeError:
        return False
    return isinstance(data.get("cve_rows"), list)


def _run_ready_for_plat_sync(run: ProcessingRun) -> bool:
    """True when findings exist and the run is not mid-pipeline or mid-sync."""
    st = (run.status or "").strip()
    if st in _PLAT_SYNC_IN_PROGRESS or st in _PIPELINE_ACTIVE:
        return False
    if not _run_has_cve_rows(run):
        return False
    if st == "done" or st == "cancelled":
        return True
    return st.startswith("failed")


@app.post("/api/jobs/{run_id}/sync-plat")
def enqueue_sync_plat(run_id: str):
    try:
        rid = uuid.UUID(run_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid run id") from e
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run:
            raise HTTPException(status_code=404, detail="run not found")
        if (run.status or "") in _PLAT_SYNC_IN_PROGRESS:
            raise HTTPException(status_code=409, detail="PLAT sync already in progress")
        if not _run_ready_for_plat_sync(run):
            st = (run.status or "").strip()
            if not _run_has_cve_rows(run):
                raise HTTPException(status_code=400, detail="no result to sync")
            if st in _PIPELINE_ACTIVE or st == "queued":
                raise HTTPException(
                    status_code=400,
                    detail="run must be finished before PLAT sync",
                )
            raise HTTPException(
                status_code=400,
                detail=f"cannot sync PLAT for run status {st!r}",
            )
    async_result = sync_plat_for_run.delay(str(rid))
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if run:
            run.celery_task_id = async_result.id
            db.add(run)
            db.commit()
    return {"task_id": async_result.id}


@app.post("/api/jobs/{run_id}/cancel")
def cancel_run(run_id: str):
    """Terminate an in-progress processing or sync run."""
    try:
        rid = uuid.UUID(run_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid run id") from e
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run:
            raise HTTPException(status_code=404, detail="run not found")
        terminal = {"done", "cancelled"}
        if run.status in terminal or (run.status or "").startswith("failed"):
            raise HTTPException(status_code=409, detail=f"run already in terminal state: {run.status}")
        task_id = run.celery_task_id
        if task_id:
            from worker.app.celery_app import celery_app as _celery
            _celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
        st = (run.status or "").strip()
        if st in _PLAT_SYNC_IN_PROGRESS and _run_has_cve_rows(run):
            # Findings are already built; cancelling sync should not block the next sync.
            try:
                data = json.loads(run.result_json or "{}")
            except json.JSONDecodeError:
                data = {}
            data.pop("_plat_sync_progress", None)
            run.result_json = json.dumps(data)
            run.status = "done"
        else:
            run.status = "cancelled"
        db.add(run)
        db.commit()
    return {"ok": True}


class CveRowPatchIn(BaseModel):
    cve_id: str
    affected_version: str | None = None
    affected_resource: str | None = None
    image_basename: str | None = None
    force_refresh_aqua: bool = False


@app.patch("/api/jobs/{run_id}/cve-row")
def patch_cve_row(run_id: str, payload: CveRowPatchIn):
    """Persist a manual field override on a specific CVE row within a run's result_json."""
    rid = uuid.UUID(run_id)
    aqua_out: dict | None = None
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run or not run.result_json:
            raise HTTPException(status_code=404, detail="run not found")
        data = json.loads(run.result_json)
        rows: list[dict] = data.get("cve_rows") or []
        patched = False
        for row in rows:
            if row.get("cve_id") != payload.cve_id:
                continue
            if payload.affected_version is not None:
                row["affected_version"] = payload.affected_version or None
            if payload.affected_resource is not None:
                bn = (payload.image_basename or "").strip()
                canonical_resource = canonical_single_package_name(payload.affected_resource)
                if not bn:
                    # Only update row-level resource when no image is specified
                    row["affected_resource"] = canonical_resource
                search = canonical_resource or ""
                if search and (settings.aqua_api_key or "").strip():
                    basenames = image_basenames_for_cve_row(row)
                    if not bn:
                        bn = basenames[0] if basenames else ""
                    tag = settings.aqua_default_image_tag
                    if bn:
                        for img in row.get("affected_images") or []:
                            if _image_path_basename(str(img.get("image") or "")).lower() == bn.lower():
                                t = (img.get("tag") or "").strip()
                                if t:
                                    tag = t
                                break
                    nvd_name = None
                    pkgs = row.get("all_packages") or []
                    if pkgs and isinstance(pkgs[0], dict):
                        nvd_name = (pkgs[0].get("product") or "").strip() or None
                    aqua_search = resolve_aqua_search_name(pkgs, search)
                    result = cross_check_package(
                        db,
                        bn,
                        aqua_search,
                        tag=tag,
                        customer_name=search,
                        nvd_name=nvd_name,
                        nvd_packages=pkgs,
                        force_refresh=payload.force_refresh_aqua,
                    )
                    # Update legacy shape
                    by_image = dict(row.get("aqua_pkg_by_image") or {})
                    # Update new per-image shape
                    pkg_by_image = dict(row.get("package_by_image") or {})
                    new_entry = {
                        "affected_resource": search,
                        "aqua_pkg_found": result.found if result.aqua_checked else None,
                        "aqua_package_name": result.aqua_package_name,
                        "aqua_package_version": result.aqua_package_version,
                        "aqua_candidates": candidates_to_json(result.candidates),
                        "aqua_checked": result.aqua_checked,
                        "aqua_tag_requested": result.aqua_tag_requested,
                        "aqua_tag_used": result.aqua_tag_used,
                    }
                    if bn:
                        by_image[bn] = {
                            "found": result.found,
                            "aqua_package_name": result.aqua_package_name,
                            "aqua_package_version": result.aqua_package_version,
                            "candidates": candidates_to_json(result.candidates),
                            "aqua_checked": result.aqua_checked,
                        }
                        pkg_by_image[bn] = new_entry
                        row["aqua_pkg_by_image"] = by_image
                        row["package_by_image"] = pkg_by_image
                    # Recompute row-level rollups
                    if result.aqua_checked:
                        all_checked = [
                            e for e in pkg_by_image.values()
                            if e.get("aqua_checked")
                        ]
                        row["aqua_pkg_found"] = all(
                            e.get("aqua_pkg_found") is True for e in all_checked
                        ) if all_checked else result.found
                        row["aqua_package_name"] = result.aqua_package_name
                        if not result.found:
                            row["aqua_candidates"] = candidates_to_json(result.candidates)
                        else:
                            row.pop("aqua_candidates", None)
                    aqua_out = {
                        "aqua_pkg_found": row.get("aqua_pkg_found"),
                        "aqua_package_name": row.get("aqua_package_name"),
                        "aqua_candidates": row.get("aqua_candidates"),
                        "affected_resource": row.get("affected_resource"),
                        "package_by_image_entry": new_entry if bn else None,
                        "package_by_image": row.get("package_by_image"),
                    }
            patched = True
        if not patched:
            raise HTTPException(status_code=404, detail="cve_id not found in run")
        data["cve_rows"] = rows
        run.result_json = json.dumps(data)
        db.add(run)
        db.commit()
    out: dict = {"ok": True}
    if aqua_out:
        out.update(aqua_out)
    return out


@app.get("/api/aqua-packages")
def aqua_packages_catalog():
    return list_aqua_package_catalog()


@app.get("/api/aqua-packages/settings")
def aqua_packages_settings_get():
    return get_aqua_packages_settings()


@app.patch("/api/aqua-packages/settings")
def aqua_packages_settings_patch(payload: AquaPackagesSettingsIn):
    return patch_aqua_packages_settings(payload)


@app.get("/api/aqua-packages/entry")
def aqua_packages_entry(
    registry: str = Query(...),
    repository: str = Query(...),
    tag: str = Query(...),
):
    return get_aqua_package_entry(registry, repository, tag)


@app.delete("/api/aqua-packages/entry")
def aqua_packages_entry_delete(
    registry: str = Query(...),
    repository: str = Query(...),
    tag: str = Query(...),
):
    return delete_aqua_cache_entry(registry, repository, tag)


@app.post("/api/aqua-packages/refresh")
def aqua_packages_refresh(payload: AquaPackagesRefreshIn):
    return refresh_aqua_cache_entry(payload)


@app.get("/api/jobs/{run_id}")
def job_status(run_id: str):
    rid = uuid.UUID(run_id)
    with db_session() as db:
        run = db.get(ProcessingRun, rid)
        if not run:
            raise HTTPException(status_code=404, detail="run not found")
        result = json.loads(run.result_json) if run.result_json else None
        return {
            "run_id": str(run.id),
            "issue_key": run.issue_key,
            "status": run.status,
            "task_id": run.celery_task_id,
            "updated_at": run.updated_at.isoformat() if run.updated_at else None,
            "result": result,
        }


# Mount React SPA — must be last, after all API routes.
# StaticFiles with html=True serves index.html for any unmatched path (SPA routing).
# Only active when dist/ exists (combined portal container); skipped in bare API dev.
import os as _os
if _os.path.isdir("dist"):
    app.mount("/", StaticFiles(directory="dist", html=True), name="static")
