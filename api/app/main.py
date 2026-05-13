import json
import uuid
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, field_validator

from api.app.cve_row_derived import (
    cve_rows_from_result,
    derive_cve_state,
    plat_keys_aggregate_from_rows,
)
from api.app.jira_client import JiraClient
from api.app.db import engine, db_session
from api.app.models import Base, CustomerSla, ProcessingRun
from api.app.sla_commitment import due_date_from_anchor, parse_jira_created
from api.app.parsing import normalize_description
from worker.app.tasks import process_issue


app = FastAPI(title="CVE Portal API", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health():
    return {"ok": True}


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


@app.post("/api/plat")
def create_plat_ticket(payload: CreatePlatIn):
    jira = JiraClient()
    try:
        existing = jira.find_plat_security_for_image(
            payload.cve_id.strip(),
            payload.image_basename.strip(),
        )
        if existing:
            return {"exists": True, "keys": existing}
        org_refs = [r.model_dump(exclude_none=True) for r in (payload.organizations or [])]
        key = jira.create_plat_security_vulnerability(
            payload.cve_id.strip(),
            payload.image_basename.strip(),
            payload.package_name.strip(),
            payload.package_version.strip(),
            priority_name=_jira_priority_name(payload.severity),
            organization_refs=org_refs or None,
            source_issue_key=payload.source_issue_key,
        )
        if not key:
            raise HTTPException(status_code=502, detail="Jira did not return issue key")
        return {"exists": False, "key": key}
    except httpx.HTTPStatusError as e:
        detail = e.response.text if e.response is not None else str(e)
        raise HTTPException(status_code=400, detail=detail) from e
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    finally:
        jira.close()


@app.post("/api/plat/bug")
def create_plat_bug_ticket(payload: CreatePlatIn):
    jira = JiraClient()
    try:
        cve_id = payload.cve_id.strip()
        image_basename = payload.image_basename.strip()
        existing = jira.find_plat_bug_for_image(cve_id, image_basename)
        if existing:
            return {"exists": True, "keys": existing}
        org_refs = [r.model_dump(exclude_none=True) for r in (payload.organizations or [])]
        key = jira.create_plat_bug(
            cve_id,
            image_basename,
            payload.package_name.strip(),
            payload.package_version.strip(),
            priority_name=_jira_priority_name(payload.severity),
            organization_refs=org_refs or None,
            source_issue_key=payload.source_issue_key,
            image_display=payload.image_display,
            resource_label=payload.resource_label,
            vendor_fix_version=payload.vendor_fix_version,
        )
        if not key:
            raise HTTPException(status_code=502, detail="Jira did not return issue key")
        summary = f"[{cve_id}] - [{image_basename}]"
        return {"exists": False, "key": key, "summary": summary}
    except httpx.HTTPStatusError as e:
        detail = e.response.text if e.response is not None else str(e)
        raise HTTPException(status_code=400, detail=detail) from e
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


@app.post("/api/issues/{issue_key}/process")
def start_processing(issue_key: str):
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

    out: list[dict] = []
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
        out.append(
            {
                "issue_key": r.issue_key,
                "parent_issue_key": parent_issue_key,
                "issue_project": issue_project,
                "run_id": str(r.id),
                "run_status": r.status,
                "ticket_status": ticket_status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "cve_count": cve_count,
                "needs_plat_cve_count": needs_plat,
                "plat_keys": plat_keys,
                "cves": cves,
            }
        )
    return out


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
            "result": result,
        }

