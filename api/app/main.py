import json
import uuid

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from api.app.jira_client import JiraClient
from api.app.db import engine, db_session
from api.app.models import Base, ProcessingRun
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

