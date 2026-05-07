from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from api.app.config import settings


def _basic_auth_header(email: str, token: str) -> str:
    raw = f"{email}:{token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _text_to_adf(text: str) -> dict[str, Any]:
    # Minimal Atlassian Document Format: paragraph(s) with hardBreaks.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    content: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for line in lines:
        if line == "":
            if current:
                content.append({"type": "paragraph", "content": current})
                current = []
            else:
                content.append({"type": "paragraph", "content": []})
            continue
        if current:
            current.append({"type": "hardBreak"})
        current.append({"type": "text", "text": line})
    if current:
        content.append({"type": "paragraph", "content": current})
    return {"type": "doc", "version": 1, "content": content}


@dataclass(frozen=True)
class JiraIssueSummary:
    key: str
    summary: str | None
    issuetype: str | None
    project: str | None
    description_raw: Any
    attachments: list[dict[str, Any]]
    reporter: str | None
    organizations: list[str]


class JiraClient:
    def __init__(self) -> None:
        self._base = settings.jira_base_url.rstrip("/")
        self._headers = {
            "Authorization": _basic_auth_header(settings.jira_email, settings.jira_api_token),
            "Accept": "application/json",
        }
        self._client = httpx.Client(headers=self._headers, timeout=30.0, follow_redirects=True)

    def close(self) -> None:
        self._client.close()

    def get_issue(self, issue_key: str) -> JiraIssueSummary:
        url = f"{self._base}/rest/api/3/issue/{issue_key}"
        params = {
            "fields": ",".join(
                [
                    "summary",
                    "description",
                    "attachment",
                    "issuetype",
                    "project",
                    "reporter",
                    "customfield_10403",  # Organizations (JSM)
                ]
            )
        }
        r = self._client.get(url, params=params)
        r.raise_for_status()
        data = r.json()
        fields = data.get("fields") or {}
        attachments = fields.get("attachment") or []
        raw_orgs = fields.get("customfield_10403") or []
        return JiraIssueSummary(
            key=data.get("key", issue_key),
            summary=fields.get("summary"),
            issuetype=(fields.get("issuetype") or {}).get("name"),
            project=(fields.get("project") or {}).get("key"),
            description_raw=fields.get("description"),
            attachments=[
                {
                    "id": a.get("id"),
                    "filename": a.get("filename"),
                    "mimeType": a.get("mimeType"),
                    "size": a.get("size"),
                    "content": a.get("content"),
                }
                for a in attachments
            ],
            reporter=(fields.get("reporter") or {}).get("displayName"),
            organizations=[o.get("name", "") for o in raw_orgs if o.get("name")],
        )

    def search_cve_ticket(self, cve_id: str) -> str | None:
        """Return the first PLAT Security Vulnerability ticket key whose CVE ID field matches, or None."""
        url = f"{self._base}/rest/api/3/search/jql"
        payload = {
            "jql": (
                f'project = PLAT AND issuetype = "Security Vulnerability" '
                f'AND cf[11245] = "{cve_id}"'
            ),
            "fields": ["key"],
            "maxResults": 1,
        }
        headers = dict(self._headers)
        headers["Content-Type"] = "application/json"
        r = self._client.post(url, json=payload, headers=headers)
        r.raise_for_status()
        issues = r.json().get("issues") or []
        return issues[0]["key"] if issues else None

    def download_attachment(self, content_url: str) -> bytes:
        r = self._client.get(content_url)
        r.raise_for_status()
        return r.content

    def add_comment(self, issue_key: str, comment_text: str, internal: bool = True) -> dict[str, Any]:
        # If Jira Service Management internal comments are enabled, use servicedesk API.
        # Otherwise, fall back to regular Jira comment (no internal/public distinction).
        if internal and settings.jira_use_jsm_internal_comments:
            url = f"{self._base}/rest/servicedeskapi/request/{issue_key}/comment"
            payload = {"body": comment_text, "public": False}
            headers = dict(self._headers)
            headers["Content-Type"] = "application/json"
            r = self._client.post(url, json=payload, headers=headers)
            r.raise_for_status()
            return r.json()

        url = f"{self._base}/rest/api/3/issue/{issue_key}/comment"
        payload = {"body": _text_to_adf(comment_text)}
        headers = dict(self._headers)
        headers["Content-Type"] = "application/json"
        r = self._client.post(url, json=payload, headers=headers)
        r.raise_for_status()
        return r.json()

