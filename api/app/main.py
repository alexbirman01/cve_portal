import json
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

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

