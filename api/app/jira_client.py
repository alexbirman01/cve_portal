from __future__ import annotations

import base64
import datetime as dt
import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

from api.app.config import settings
from api.app.plat_organization_labels import plat_organization_name_allowed
from api.app.sla_commitment import parse_jira_created


def _jira_fix_versions_display(raw: Any) -> str:
    if not raw or not isinstance(raw, list):
        return ""
    names: list[str] = []
    for x in raw:
        if isinstance(x, dict):
            n = x.get("name")
            if n is not None and str(n).strip():
                names.append(str(n).strip())
        elif x is not None and str(x).strip():
            names.append(str(x).strip())
    return ", ".join(names)


def _jira_tag_numbers_display(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (str, int, float)):
        return str(raw).strip()
    if isinstance(raw, dict):
        v = raw.get("value")
        if v is None:
            v = raw.get("name")
        return str(v).strip() if v is not None else ""
    if isinstance(raw, list):
        parts = [_jira_tag_numbers_display(x) for x in raw]
        return ", ".join(p for p in parts if p)
    return str(raw).strip()


def _jira_duedate_str(raw: str | None) -> str | None:
    """Normalize SLA/API date to Jira system field `duedate` (YYYY-MM-DD)."""
    if raw is None:
        return None
    s = str(raw).strip()
    if len(s) >= 10:
        s = s[:10]
    if len(s) != 10:
        return None
    try:
        dt.datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None
    return s


def _plat_organization_field_ids() -> list[str]:
    """`JIRA_PLAT_ORGANIZATION_FIELD_ID` may be comma-separated; order preserved, duplicates dropped."""
    raw = (settings.jira_plat_organization_field_id or "").strip()
    merge_raw = (settings.jira_plat_organization_field_id_merge or "").strip()
    seen: set[str] = set()
    out: list[str] = []
    for segment in (raw, merge_raw):
        if not segment:
            continue
        for part in segment.split(","):
            p = part.strip()
            if not p:
                continue
            k = p.casefold()
            if k in seen:
                continue
            seen.add(k)
            out.append(p)
    return out


def _plat_organization_field_ids_for_read() -> list[str]:
    """
    Fields to GET when copying Organization from a source issue. May differ from create: portal tickets often
    still expose org on `customfield_10403` while PLAT create uses `customfield_10727` with `value` objects.
    """
    out: list[str] = []
    seen: set[str] = set()
    for fid in _plat_organization_field_ids():
        k = fid.casefold()
        if k not in seen:
            seen.add(k)
            out.append(fid)
    extra = (settings.jira_plat_organization_read_field_ids_extra or "").strip()
    parts = [p.strip() for p in extra.split(",") if p.strip()] if extra else ["customfield_10403"]
    for p in parts:
        k = p.casefold()
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def _plat_default_organization_refs() -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    raw = (settings.jira_plat_default_organization_names or "").strip()
    if not raw:
        return refs
    seen: set[str] = set()
    for part in raw.split(","):
        s = part.strip()
        if not s:
            continue
        k = s.casefold()
        if k in seen:
            continue
        seen.add(k)
        refs.append({"name": s})
    return refs


def _plat_organization_field_id_set() -> set[str]:
    return {x.casefold() for x in _plat_organization_field_ids()}


def _plat_organization_create_field_groups(org_fids: list[str]) -> list[list[str]]:
    """
    When multiple org-related CFs are configured, try the **first** configured CF alone, then the full set.
    Avoids one bad field invalidating create for the other (order is from `JIRA_PLAT_ORGANIZATION_FIELD_ID` + merge).
    """
    if not org_fids:
        return []
    if len(org_fids) == 1:
        return [org_fids]
    return [[org_fids[0]], org_fids]


def _plat_extra_organization_tokens_from_settings() -> list[str]:
    s = (settings.jira_plat_extra_organizations or "").strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def _normalize_cf_value(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        s = raw.strip()
        return s or None
    if isinstance(raw, dict):
        s = (raw.get("value") or raw.get("name") or "").strip()
        return s or None
    s = str(raw).strip()
    return s or None


def _image_basename_from_correlation(correlation_id: str | None, cve_id: str) -> str | None:
    if not correlation_id:
        return None
    suffix = "_" + cve_id
    if correlation_id.endswith(suffix):
        stem = correlation_id[: -len(suffix)].strip()
        return stem or None
    return None


def _image_basename_from_summary(summary: str | None, cve_id: str) -> str | None:
    if not summary:
        return None
    m = re.match(
        r"^\s*\[" + re.escape(cve_id) + r"\]\s*-\s*\[([^\]]+)\]\s*$",
        summary.strip(),
    )
    if m:
        s = m.group(1).strip()
        return s or None
    return None


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


def _plat_bug_description_text(
    *,
    image_display: str,
    resource: str,
    vendor_affected_version: str,
    vendor_fix_version: str,
) -> str:
    """Plain-text body for PLAT Bug description (Jira ADF via `_text_to_adf`)."""
    img = image_display.strip() or "—"
    res = resource.strip() or "—"
    va = vendor_affected_version.strip() or "—"
    vf = vendor_fix_version.strip() or "—"
    return (
        f" Image:    {img}\n"
        f"Resource: {res}\n"
        f"Vendor Affected version: {va}\n"
        f"Vendor Fix version: {vf}"
    )


def _jira_select_like_value_for_create(raw: Any) -> dict[str, Any] | None:
    """Map a Jira GET field value (select / option) to a minimal POST shape."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        v = raw.get("value")
        if v is not None and str(v).strip():
            return {"value": str(v).strip()}
        n = raw.get("name")
        if n is not None and str(n).strip():
            return {"value": str(n).strip()}
        oid = raw.get("id")
        if oid is not None and str(oid).strip():
            s = str(oid).strip()
            if s.isdigit():
                return {"id": int(s)}
            return {"id": s}
    return None


def _plat_bug_dev_group_value_list_for_create(raw: Any, fallback_csv: str) -> list[dict[str, Any]] | None:
    """
    Dev Group (customfield_10712) is a multi-select: REST create uses a list, e.g. [{"value":"BE"}].
    `fallback_csv` may be one label or comma-separated labels.
    """
    if raw is not None:
        if isinstance(raw, list):
            out: list[dict[str, Any]] = []
            for item in raw:
                x = _jira_select_like_value_for_create(item)
                if x:
                    out.append(x)
            if out:
                return out
        else:
            x = _jira_select_like_value_for_create(raw)
            if x:
                return [x]
    parts = [p.strip() for p in (fallback_csv or "").split(",") if p.strip()]
    if parts:
        return [{"value": p} for p in parts]
    return None


def _coerce_jira_organization_id(raw: Any) -> int | None:
    """Parse a strictly numeric org id (e.g. for JQL); use `_jsm_org_id_token` for REST values."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    s = str(raw).strip()
    if s.isdigit():
        return int(s)
    return None


def _jsm_org_id_token(raw: Any) -> str | None:
    """Organization id as returned by JSM (`id` may be a decimal or opaque string)."""
    if raw is None or isinstance(raw, bool):
        return None
    s = str(raw).strip()
    return s or None


def _merge_jira_organization_ids(
    refs: list[dict[str, Any]] | None,
    extra_tokens: list[str],
) -> list[str]:
    """Fallback: use id tokens from refs / env (strings as returned by Jira)."""
    seen: set[str] = set()
    out: list[str] = []
    for r in refs or []:
        if not isinstance(r, dict):
            continue
        tok = _jsm_org_id_token(r.get("id"))
        if tok is not None and tok not in seen:
            seen.add(tok)
            out.append(tok)
    for raw in extra_tokens:
        tok = (raw or "").strip()
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def _jsm_org_name_to_raw_maps(
    values: list[dict[str, Any]],
) -> tuple[dict[str, str], set[str]]:
    """Map lowercased name → organization id token; `valid_raw` is the set of known directory ids."""
    by_name: dict[str, str] = {}
    valid_raw: set[str] = set()
    for v in values:
        if not isinstance(v, dict):
            continue
        name = str(v.get("name") or "").strip()
        tok = _jsm_org_id_token(v.get("id"))
        if tok is None:
            continue
        valid_raw.add(tok)
        if name:
            by_name[name.casefold()] = tok
    return by_name, valid_raw


def _org_field_put_bodies(fid: str, v: Any) -> list[dict[str, Any]]:
    """Issue edit payloads to try for the Organization multi-value field (v3 `update` vs `fields`, `set`, `add`)."""
    bodies: list[dict[str, Any]] = []
    sig: set[str] = set()

    def add(body: dict[str, Any]) -> None:
        key = json.dumps(body, sort_keys=True)
        if key not in sig:
            sig.add(key)
            bodies.append(body)

    add({"update": {fid: v}})
    add({"update": {fid: [{"set": v}]}})
    add({"fields": {fid: v}})
    if isinstance(v, list) and v:
        if all(isinstance(x, int) for x in v):
            add({"update": {fid: [{"add": x} for x in v]}})
        if all(isinstance(x, str) and x.isdigit() for x in v):
            add({"update": {fid: [{"add": int(x)} for x in v]}})
        if all(isinstance(x, dict) for x in v):
            add({"update": {fid: [{"add": x} for x in v]}})
    return bodies


def _org_field_put_bodies_for_fids(fids: list[str], v: Any) -> list[dict[str, Any]]:
    """Same as `_org_field_put_bodies` but set Organization on several custom fields in one payload."""
    if not fids:
        return []
    if len(fids) == 1:
        return _org_field_put_bodies(fids[0], v)
    bodies: list[dict[str, Any]] = []
    sig: set[str] = set()

    def add(body: dict[str, Any]) -> None:
        key = json.dumps(body, sort_keys=True)
        if key not in sig:
            sig.add(key)
            bodies.append(body)

    fm = {f: v for f in fids}
    add({"update": dict(fm)})
    add({"update": {f: [{"set": v}] for f in fids}})
    add({"fields": dict(fm)})
    if isinstance(v, list) and v:
        if all(isinstance(x, int) for x in v):
            add({"update": {f: [{"add": x} for x in v] for f in fids}})
        if all(isinstance(x, str) and x.isdigit() for x in v):
            add({"update": {f: [{"add": int(x)} for x in v] for f in fids}})
        if all(isinstance(x, dict) for x in v):
            add({"update": {f: [{"add": x} for x in v] for f in fids}})
    return bodies


def _org_field_value_transforms_for_jira(
    raw_tokens: list[str],
    *,
    display_names: list[str] | None = None,
) -> list[Any]:
    """
    JSON shapes for Organization on issue create/edit.
    PlainID PLAT: `[{"value": "Humana"}]` (select / org labels). Other sites use id-based arrays from JSM.
    """
    variants: list[Any] = []
    sig: set[str] = set()

    def add(payload: list[Any]) -> None:
        key = json.dumps(payload, sort_keys=True)
        if key not in sig:
            sig.add(key)
            variants.append(json.loads(json.dumps(payload)))

    names: list[str] = []
    seen_n: set[str] = set()
    for n in display_names or []:
        s = (n or "").strip()
        if not s:
            continue
        k = s.casefold()
        if k in seen_n:
            continue
        seen_n.add(k)
        names.append(s)

    if names:
        add([{"value": n} for n in names])
        add([{"name": n} for n in names])

    toks = [t.strip() for t in raw_tokens if t and str(t).strip()]
    if not toks:
        return variants

    # Id-based shapes (servicedesk directory ids, etc.)
    if all(s.isdigit() for s in toks):
        add([{"id": int(s)} for s in toks])
        add([{"id": s} for s in toks])
        add([int(s) for s in toks])
        add([str(x) for x in toks])
        add([{"organizationId": int(s)} for s in toks])
        add([{"organizationId": s} for s in toks])
    else:
        add([{"id": s} for s in toks])
        add([str(x) for x in toks])

    return variants


def _response_targets_org_field(text: str, fids: list[str]) -> bool:
    """True if Jira response is specifically about the Organization / org custom field (any wording)."""
    if not text:
        return False
    t = text
    for fid in fids:
        if fid and fid in t:
            return True
    tl = t.lower()
    return (
        "customfield_10403" in t
        or "customfield_10727" in t
        or "Invalid organization" in t
        or "organizations" in tl
        or '"organization"' in tl
        or ("organization" in tl and "array" in tl)
    )


def _normalize_raw_organizations_field(raw: Any) -> list[Any]:
    """API may return a list of org objects or a single org object."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return []


@dataclass(frozen=True)
class PlatTicket:
    key: str
    issue_type: str          # "Security Vulnerability" or "Bug"
    summary: str | None = None


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
    organization_refs: list[dict[str, Any]]
    created: dt.datetime | None = None


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

    def list_jsm_organizations(self) -> list[dict[str, Any]]:
        """Canonical org list for the site (`GET /rest/servicedeskapi/organization`)."""
        out: list[dict[str, Any]] = []
        start = 0
        limit = 50
        try:
            while True:
                r = self._client.get(
                    f"{self._base}/rest/servicedeskapi/organization",
                    params={"start": start, "limit": limit},
                )
                r.raise_for_status()
                data = r.json()
                values = data.get("values") or []
                out.extend(values)
                if len(values) < limit:
                    break
                start += limit
        except Exception:
            return []
        return out

    def _organization_refs_from_jsm_request_api(self, issue_key: str) -> list[dict[str, Any]]:
        """Parse Organization from JSM customer request API when issue GET missed it."""
        if not settings.jira_plat_try_jsm_request_api_for_organization:
            return []
        try:
            r = self._client.get(
                f"{self._base}/rest/servicedeskapi/request/{issue_key.strip()}",
                params={"expand": "requestFieldValues"},
            )
            if not r.is_success:
                return []
            data = r.json()
        except Exception:
            return []

        org_fids = {x.casefold() for x in _plat_organization_field_ids()}
        read_extra = (settings.jira_plat_organization_read_field_ids_extra or "").strip()
        for p in [x.strip() for x in read_extra.split(",") if x.strip()]:
            org_fids.add(p.casefold())
        org_fids.add("customfield_10403")
        org_fids.add("customfield_10727")

        def append_ref(entry: dict[str, Any], bag: list[dict[str, Any]], dedupe: set[str]) -> None:
            oid = entry.get("id")
            onm = entry.get("name")
            dk = (str(oid).strip() if oid else "") or (str(onm).strip() if onm else "")
            if not dk:
                return
            k = dk.casefold()
            if k in dedupe:
                return
            dedupe.add(k)
            bag.append(entry)

        out: list[dict[str, Any]] = []
        seen: set[str] = set()

        for rv in data.get("requestFieldValues") or []:
            if not isinstance(rv, dict):
                continue
            fid = str(rv.get("fieldId") or "").strip()
            label = str(rv.get("label") or "").strip().casefold()
            if fid.casefold() not in org_fids and "organization" not in label:
                continue
            val = rv.get("value")
            if isinstance(val, str) and val.strip():
                append_ref({"name": val.strip()}, out, seen)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.strip():
                        append_ref({"name": item.strip()}, out, seen)
                    elif isinstance(item, dict):
                        entry: dict[str, Any] = {}
                        tid = item.get("id")
                        if tid is None:
                            tid = item.get("organizationId")
                        if tid is not None and str(tid).strip():
                            entry["id"] = str(tid).strip()
                        nm = item.get("name")
                        if (nm is None or not str(nm).strip()) and item.get("value") is not None:
                            nm = item.get("value")
                        if nm is not None and str(nm).strip():
                            entry["name"] = str(nm).strip()
                        if entry:
                            append_ref(entry, out, seen)
            elif isinstance(val, dict):
                entry = {}
                tid = val.get("id") or val.get("organizationId")
                if tid is not None and str(tid).strip():
                    entry["id"] = str(tid).strip()
                nm = val.get("name") or val.get("value")
                if nm is not None and str(nm).strip():
                    entry["name"] = str(nm).strip()
                if entry:
                    append_ref(entry, out, seen)

        return out

    def _collect_organization_refs_for_plat(
        self,
        organization_refs: list[dict[str, Any]] | None,
        source_issue_key: str | None,
    ) -> list[dict[str, Any]]:
        tokens = _plat_extra_organization_tokens_from_settings()
        payload_refs = [
            dict(x)
            for x in (organization_refs or [])
            if isinstance(x, dict) and ((x.get("id") is not None and str(x.get("id")).strip()) or (x.get("name") is not None and str(x.get("name")).strip()))
        ]
        refs: list[dict[str, Any]] = []
        src_key = (source_issue_key or "").strip()
        source_refs: list[dict[str, Any]] = []
        if settings.jira_plat_use_source_issue_organizations and src_key:
            try:
                source_refs = list(self.get_issue(src_key).organization_refs)
            except Exception:
                pass
            if not source_refs:
                source_refs = self._organization_refs_from_jsm_request_api(src_key)

        # Organization on the original portal ticket wins when `source_issue_key` is set.
        if settings.jira_plat_use_source_issue_organizations and source_refs:
            refs = source_refs
        else:
            refs = list(payload_refs)

        for t in tokens:
            tok = (t or "").strip()
            if not tok:
                continue
            if tok.isdigit():
                refs.append({"id": tok})
            else:
                refs.append({"name": tok})
        if settings.jira_plat_restrict_organization_names_to_enum:
            refs = [
                r
                for r in refs
                if isinstance(r, dict)
                and (
                    r.get("id")
                    or not (r.get("name") or "").strip()
                    or plat_organization_name_allowed(str(r.get("name") or ""), restrict_to_enum=True)
                )
            ]
        if not refs:
            refs.extend(_plat_default_organization_refs())
        return refs

    def get_issue(self, issue_key: str) -> JiraIssueSummary:
        url = f"{self._base}/rest/api/3/issue/{issue_key}"
        org_ids = _plat_organization_field_ids_for_read()
        params = {
            "fields": ",".join(
                [
                    "summary",
                    "description",
                    "attachment",
                    "issuetype",
                    "project",
                    "reporter",
                    "created",
                    *org_ids,
                ]
            )
        }
        r = self._client.get(url, params=params)
        r.raise_for_status()
        data = r.json()
        fields = data.get("fields") or {}
        attachments = fields.get("attachment") or []
        org_refs: list[dict[str, Any]] = []
        org_names: list[str] = []
        dedupe: set[str] = set()
        for ofid in org_ids:
            raw_orgs = _normalize_raw_organizations_field(fields.get(ofid))
            for o in raw_orgs:
                if not isinstance(o, dict):
                    continue
                oid = o.get("id")
                if oid is None:
                    oid = o.get("organizationId")
                oname = o.get("name")
                if (oname is None or not str(oname).strip()) and o.get("value") is not None:
                    oname = o.get("value")
                entry: dict[str, Any] = {}
                if oid is not None and str(oid).strip():
                    entry["id"] = str(oid).strip()
                if oname is not None and str(oname).strip():
                    entry["name"] = str(oname).strip()
                if not entry:
                    continue
                dk = entry.get("id") or entry.get("name") or ""
                dk_l = str(dk).strip().casefold()
                if dk_l and dk_l in dedupe:
                    continue
                if dk_l:
                    dedupe.add(dk_l)
                org_refs.append(entry)
                if entry.get("name"):
                    org_names.append(entry["name"])
                elif entry.get("id"):
                    org_names.append(str(entry["id"]))
        created_val = fields.get("created")
        created_dt: dt.datetime | None = None
        if isinstance(created_val, str):
            created_dt = parse_jira_created(created_val)
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
            organizations=org_names,
            organization_refs=org_refs,
            created=created_dt,
        )

    def search_plat_security_for_cve(self, cve_id: str) -> list[dict[str, str]]:
        """
        Sec-Vuln PLAT rows for this CVE. Each item: {"key", "image_basename"}.
        image_basename from correlation custom field (imagename_CVE) or summary [CVE] - [image].
        """
        url = f"{self._base}/rest/api/3/search/jql"
        headers = {**self._headers, "Content-Type": "application/json"}
        jql = (
            f'project = {settings.jira_plat_project_key} AND issuetype = "{settings.jira_plat_issuetype_name}" '
            f'AND cf[{settings.jira_plat_cve_cf_number}] = "{cve_id}"'
        )
        fields = ["key", "summary"]
        fid = settings.jira_plat_cf_internal_id
        if fid:
            fields.append(fid)
        try:
            r = self._client.post(
                url,
                json={"jql": jql, "fields": fields, "maxResults": 100},
                headers=headers,
            )
            r.raise_for_status()
            out: list[dict[str, str]] = []
            for issue in r.json().get("issues") or []:
                key = issue.get("key", "")
                f = issue.get("fields") or {}
                img: str | None = None
                if fid:
                    img = _image_basename_from_correlation(_normalize_cf_value(f.get(fid)), cve_id)
                if not img:
                    img = _image_basename_from_summary(f.get("summary"), cve_id)
                out.append({"key": key, "image_basename": (img or "").strip()})
            return out
        except Exception:
            return []

    def search_plat_security_keys(self, cve_id: str) -> list[str]:
        """Keys of PLAT Security Vulnerability issues with this CVE (custom CVE field)."""
        return [x["key"] for x in self.search_plat_security_for_cve(cve_id)]

    def find_plat_security_for_image(self, cve_id: str, image_basename: str) -> list[str]:
        want = image_basename.strip().casefold()
        if not want:
            return []
        return [
            item["key"]
            for item in self.search_plat_security_for_cve(cve_id)
            if (item.get("image_basename") or "").strip().casefold() == want
        ]

    def search_plat_bugs_for_cve(self, cve_id: str) -> list[dict[str, str]]:
        """
        Bug PLAT rows for this CVE (summary ~ cve_id). Each item: {"key", "image_basename"}.
        image_basename from correlation custom field (if present) or summary [CVE] - [image].
        """
        url = f"{self._base}/rest/api/3/search/jql"
        headers = {**self._headers, "Content-Type": "application/json"}
        jql = (
            f'project = {settings.jira_plat_project_key} AND issuetype = Bug '
            f'AND summary ~ "{cve_id}"'
        )
        fields = ["key", "summary"]
        fid = settings.jira_plat_cf_internal_id
        if fid:
            fields.append(fid)
        try:
            r = self._client.post(
                url,
                json={"jql": jql, "fields": fields, "maxResults": 100},
                headers=headers,
            )
            r.raise_for_status()
            out: list[dict[str, str]] = []
            for issue in r.json().get("issues") or []:
                key = issue.get("key", "")
                f = issue.get("fields") or {}
                img: str | None = None
                if fid:
                    img = _image_basename_from_correlation(_normalize_cf_value(f.get(fid)), cve_id)
                if not img:
                    img = _image_basename_from_summary(f.get("summary"), cve_id)
                out.append({"key": key, "image_basename": (img or "").strip()})
            return out
        except Exception:
            return []

    def find_plat_bug_for_image(self, cve_id: str, image_basename: str) -> list[str]:
        want = image_basename.strip().casefold()
        if not want:
            return []
        return [
            item["key"]
            for item in self.search_plat_bugs_for_cve(cve_id)
            if (item.get("image_basename") or "").strip().casefold() == want
        ]

    def search_plat_tickets(self, cve_id: str) -> list[PlatTicket]:
        """Return PLAT tickets related to this CVE — Security Vulnerability (by cf field) and Bug (by summary)."""
        url = f"{self._base}/rest/api/3/search/jql"
        headers = {**self._headers, "Content-Type": "application/json"}
        results: list[PlatTicket] = []

        proj = settings.jira_plat_project_key
        cfn = settings.jira_plat_cve_cf_number
        queries: list[tuple[str, str, int, list[str]]] = [
            (
                f'project = {proj} AND issuetype = "{settings.jira_plat_issuetype_name}" AND cf[{cfn}] = "{cve_id}"',
                "Security Vulnerability",
                100,
                ["key", "summary"],
            ),
            (
                f'project = {proj} AND issuetype = Bug AND summary ~ "{cve_id}"',
                "Bug",
                50,
                ["key", "summary"],  # summary needed for image-match filtering in the worker
            ),
        ]

        for jql, issue_type, max_results, fields in queries:
            try:
                r = self._client.post(
                    url,
                    json={"jql": jql, "fields": fields, "maxResults": max_results},
                    headers=headers,
                )
                r.raise_for_status()
                for issue in r.json().get("issues") or []:
                    summary = (issue.get("fields") or {}).get("summary") if issue_type == "Bug" else None
                    results.append(PlatTicket(key=issue["key"], issue_type=issue_type, summary=summary))
            except Exception:
                pass

        return results

    def _organization_ids_for_plat_create(
        self,
        organization_refs: list[dict[str, Any]] | None,
        *,
        source_issue_key: str | None = None,
    ) -> list[str]:
        """
        Organization fields (`_plat_organization_field_ids()`): same JSON array of id tokens for each custom field.
        When `jira_plat_resolve_organizations_via_servicedesk` is true, names (e.g. Accenture) are resolved via
        `GET /rest/servicedeskapi/organization`. If that list cannot be loaded, we do not fall back to ids from
        `GET issue` (those are often rejected on create).
        """
        if settings.jira_plat_skip_organization_field_on_create:
            return []
        refs = self._collect_organization_refs_for_plat(organization_refs, source_issue_key)
        if not refs:
            return []

        if settings.jira_plat_resolve_organizations_via_servicedesk:
            values = self.list_jsm_organizations()
            if not values:
                return []
            by_name, valid_raw = _jsm_org_name_to_raw_maps(values)
            seen: set[str] = set()
            out: list[str] = []
            for r in refs:
                if not isinstance(r, dict):
                    continue
                name = str(r.get("name") or "").strip()
                rid = _jsm_org_id_token(r.get("id"))
                if name:
                    nid = by_name.get(name.casefold())
                    if nid is not None and nid not in seen:
                        seen.add(nid)
                        out.append(nid)
                elif rid is not None and rid in valid_raw and rid not in seen:
                    seen.add(rid)
                    out.append(rid)
            if out:
                return out
            return []

            return _merge_jira_organization_ids(refs, [])

    def _organization_display_names_for_plat_create(
        self,
        organization_refs: list[dict[str, Any]] | None,
        *,
        source_issue_key: str | None = None,
    ) -> list[str]:
        """
        PlainID PLAT Organization field uses `[{"value": "<label>"}]` — directory display names, not numeric ids.
        """
        if settings.jira_plat_skip_organization_field_on_create:
            return []
        refs = self._collect_organization_refs_for_plat(organization_refs, source_issue_key)
        if not refs:
            return []

        id_to_name: dict[str, str] = {}
        cf_name: dict[str, str] = {}
        if settings.jira_plat_resolve_organizations_via_servicedesk:
            for v in self.list_jsm_organizations():
                if not isinstance(v, dict):
                    continue
                nm = str(v.get("name") or "").strip()
                tid = _jsm_org_id_token(v.get("id"))
                if nm:
                    cf_name[nm.casefold()] = nm
                if tid and nm:
                    id_to_name[tid.casefold()] = nm

        out: list[str] = []
        seen: set[str] = set()
        for r in refs:
            if not isinstance(r, dict):
                continue
            name = str(r.get("name") or "").strip()
            rid = _jsm_org_id_token(r.get("id"))
            chosen: str | None = None
            if name:
                chosen = cf_name.get(name.casefold(), name)
            elif rid:
                chosen = id_to_name.get(rid.casefold())
            if not chosen:
                continue
            k = chosen.casefold()
            if k in seen:
                continue
            seen.add(k)
            out.append(chosen)
        return out

    def _apply_organization_field_to_issue(
        self,
        issue_key: str,
        org_field_ids: list[str],
        org_tokens: list[str],
        *,
        organization_display_names: list[str] | None = None,
    ) -> bool:
        """Set Organization on an existing issue; try v3/v2 and several `update` / `fields` shapes."""
        if not org_field_ids:
            return True
        if not org_tokens and not organization_display_names:
            return True
        variants = _org_field_value_transforms_for_jira(
            org_tokens,
            display_names=organization_display_names,
        )
        headers = {**self._headers, "Content-Type": "application/json"}
        put_urls = [
            f"{self._base}/rest/api/3/issue/{issue_key}",
            f"{self._base}/rest/api/2/issue/{issue_key}",
        ]
        for v in variants:
            for body in _org_field_put_bodies_for_fids(org_field_ids, v):
                for put_url in put_urls:
                    r = self._client.put(put_url, json=body, headers=headers)
                    if r.is_success:
                        return True
        return False

    def _delete_issue(self, issue_key: str) -> None:
        url = f"{self._base}/rest/api/3/issue/{issue_key}"
        r = self._client.delete(url, headers=self._headers)
        r.raise_for_status()

    def _create_plat_issue_with_organization(
        self,
        base_fields: dict[str, Any],
        *,
        organization_refs: list[dict[str, Any]] | None = None,
        source_issue_key: str | None = None,
    ) -> str:
        """
        POST a PLAT issue: same Organization resolution and create/edit fallback as Security Vulnerability.
        `base_fields` must include project, summary, issuetype, and any non-org custom fields.
        """
        create_urls = (
            f"{self._base}/rest/api/3/issue",
            f"{self._base}/rest/api/2/issue",
        )
        org_tokens = self._organization_ids_for_plat_create(
            organization_refs,
            source_issue_key=source_issue_key,
        )
        org_display_names = self._organization_display_names_for_plat_create(
            organization_refs,
            source_issue_key=source_issue_key,
        )
        org_fids = _plat_organization_field_ids()
        headers = {**self._headers, "Content-Type": "application/json"}

        def post_create(fields_payload: dict[str, Any]) -> httpx.Response:
            last: httpx.Response | None = None
            for create_url in create_urls:
                last = self._client.post(
                    create_url,
                    json={"fields": fields_payload},
                    headers=headers,
                )
                if last.is_success:
                    return last
            assert last is not None
            return last

        if not org_tokens and not org_display_names:
            if settings.jira_plat_skip_organization_field_on_create:
                r = post_create(base_fields)
                r.raise_for_status()
                return str(r.json().get("key", ""))
            raise RuntimeError(
                "No Jira Organization values resolved for this create (empty list). "
                "Copy from parent: ensure the source issue exposes Organization (we GET customfield_10727 and, by default, "
                "customfield_10403). Or set JIRA_PLAT_EXTRA_ORGANIZATIONS / JIRA_PLAT_DEFAULT_ORGANIZATION_NAMES; "
                "or JIRA_PLAT_SKIP_ORGANIZATION_FIELD_ON_CREATE=true only if Jira allows missing Organization."
            )

        if not org_fids:
            raise RuntimeError(
                "JIRA_PLAT_ORGANIZATION_FIELD_ID must list at least one custom field id (comma-separated)."
            )

        variants = _org_field_value_transforms_for_jira(
            org_tokens,
            display_names=org_display_names or None,
        )
        if not variants:
            raise RuntimeError(
                "Could not build a Jira Organization JSON value (check names match Jira options or use valid org ids)."
            )
        last_org_error = ""
        for fids_try in _plat_organization_create_field_groups(org_fids):
            for v in variants:
                fields_try = dict(base_fields)
                for ofid in fids_try:
                    fields_try[ofid] = v
                for create_url in create_urls:
                    r = self._client.post(
                        create_url,
                        json={"fields": fields_try},
                        headers=headers,
                    )
                    if r.is_success:
                        key = str(r.json().get("key", ""))
                        remaining = [
                            x
                            for x in org_fids
                            if x.casefold() not in {y.casefold() for y in fids_try}
                        ]
                        if remaining:
                            self._apply_organization_field_to_issue(
                                key,
                                remaining,
                                org_tokens,
                                organization_display_names=org_display_names or None,
                            )
                        return key
                    if _response_targets_org_field(r.text or "", org_fids):
                        if r.text:
                            last_org_error = r.text
                        continue
                    r.raise_for_status()

        if not settings.jira_plat_try_bare_create_then_set_organization:
            raise RuntimeError(
                last_org_error
                or (
                    "Jira rejected every Organization payload on create. "
                    "Organization is required as an array on this issue type — verify org ids (servicedesk API / JIRA_PLAT_EXTRA_ORGANIZATIONS). "
                    "If your site only allows setting Organization after create, set JIRA_PLAT_TRY_BARE_CREATE_THEN_SET_ORGANIZATION=true."
                )
            )

        r0 = post_create(base_fields)
        r0.raise_for_status()
        key = str(r0.json().get("key", ""))
        try:
            if self._apply_organization_field_to_issue(
                key,
                org_fids,
                org_tokens,
                organization_display_names=org_display_names or None,
            ):
                return key
        except Exception:
            try:
                self._delete_issue(key)
            except Exception:
                pass
            raise
        try:
            self._delete_issue(key)
        except Exception:
            pass
        detail = (
            "Organization field could not be set on the PLAT issue; the issue was not kept. "
            + (last_org_error or "Jira rejected all organization payloads on create and on edit.")
        )
        raise RuntimeError(detail)

    def _issue_add_labels_via_update(self, issue_key: str, labels: list[str]) -> None:
        """
        Add labels using Jira REST issue edit:
        PUT .../issue/{key} with {"update": {"labels": [{"add": "..."}, ...]}}.
        """
        key = (issue_key or "").strip()
        adds = [{"add": lab.strip()} for lab in labels if lab and str(lab).strip()]
        if not key or not adds:
            return
        body: dict[str, Any] = {"update": {"labels": adds}}
        headers = {**self._headers, "Content-Type": "application/json"}
        put_urls = [
            f"{self._base}/rest/api/3/issue/{key}",
            f"{self._base}/rest/api/2/issue/{key}",
        ]
        last: httpx.Response | None = None
        for put_url in put_urls:
            last = self._client.put(put_url, json=body, headers=headers)
            if last.is_success:
                return
        err = (last.text if last is not None else "") or (str(last.status_code) if last else "unknown")
        raise RuntimeError(f"Jira could not add labels to {key}: {err}")

    def get_issue_platsync_fields(self, issue_key: str) -> dict[str, Any]:
        """Read fixVersions, tag CF, labels, duedate, issuetype for PLAT↔portal sync."""
        key = (issue_key or "").strip()
        if not key:
            return {}
        tag_fid = (settings.jira_plat_tag_numbers_field_id or "").strip()
        field_list = ["fixVersions", "labels", "duedate", "issuetype"]
        if tag_fid:
            field_list.append(tag_fid)
        params = {"fields": ",".join(field_list)}
        for path in (f"/rest/api/3/issue/{key}", f"/rest/api/2/issue/{key}"):
            try:
                r = self._client.get(f"{self._base}{path}", params=params)
                if not r.is_success:
                    continue
                fields = r.json().get("fields") or {}
                tag_raw = fields.get(tag_fid) if tag_fid else None
                return {
                    "fix_versions": _jira_fix_versions_display(fields.get("fixVersions")),
                    "tag_numbers": _jira_tag_numbers_display(tag_raw) if tag_fid else "",
                    "labels": [str(x) for x in (fields.get("labels") or [])],
                    "duedate": fields.get("duedate"),
                    "issuetype": (fields.get("issuetype") or {}).get("name"),
                }
            except Exception:
                continue
        return {}

    def ensure_plat_security_issue_sync(self, issue_key: str, desired_duedate_iso: str | None) -> None:
        """For PLAT Security Vulnerability: add CVE label; set or tighten SLA duedate (never relax)."""
        meta = self.get_issue_platsync_fields(issue_key)
        if not meta:
            return
        it = (meta.get("issuetype") or "").strip()
        want_type = (settings.jira_plat_issuetype_name or "").strip()
        if want_type and it.casefold() != want_type.casefold():
            return
        labels = [str(x) for x in (meta.get("labels") or [])]
        if "CVE" not in labels:
            self._issue_add_labels_via_update(issue_key, ["CVE"])
        dd = _jira_duedate_str(desired_duedate_iso)
        if not dd:
            return
        cur_raw = meta.get("duedate")
        cur_norm = (
            _jira_duedate_str(str(cur_raw).strip())
            if cur_raw is not None and str(cur_raw).strip()
            else None
        )
        if cur_norm is not None and dd >= cur_norm:
            return
        headers = {**self._headers, "Content-Type": "application/json"}
        body = {"fields": {"duedate": dd}}
        last: httpx.Response | None = None
        for put_url in (
            f"{self._base}/rest/api/3/issue/{issue_key.strip()}",
            f"{self._base}/rest/api/2/issue/{issue_key.strip()}",
        ):
            last = self._client.put(put_url, json=body, headers=headers)
            if last.is_success:
                return
        err = (last.text if last is not None else "") or "unknown error"
        raise RuntimeError(f"Jira could not set duedate on {issue_key}: {err}")

    def create_plat_security_vulnerability(
        self,
        cve_id: str,
        image_basename: str,
        package_name: str,
        package_vulnerable_version: str,
        *,
        priority_name: str | None = None,
        organization_refs: list[dict[str, Any]] | None = None,
        source_issue_key: str | None = None,
        due_date: str | None = None,
    ) -> str:
        """
        Create PLAT Security Vulnerability (issuetype name or id from settings).
        When Organization ids/names are present, the issue is only kept if Organization is set
        (on create or immediately after via edit). Otherwise the draft issue is deleted and an error is raised.
        """
        summary = f"[{cve_id}] - [{image_basename}]"
        internal = f"{image_basename}_{cve_id}"
        pkg = (package_name or "").strip() or cve_id

        base_fields: dict[str, Any] = {
            "project": {"key": settings.jira_plat_project_key},
            "summary": summary,
            settings.jira_plat_cf_cve_id: cve_id,
        }
        if settings.jira_plat_issuetype_id and str(settings.jira_plat_issuetype_id).strip():
            base_fields["issuetype"] = {"id": str(settings.jira_plat_issuetype_id).strip()}
        else:
            base_fields["issuetype"] = {"name": settings.jira_plat_issuetype_name}

        if priority_name:
            base_fields["priority"] = {"name": priority_name}
        int_f = (settings.jira_plat_cf_internal_id or "").strip()
        org_id_set = _plat_organization_field_id_set()
        if int_f and int_f.casefold() not in org_id_set:
            base_fields[int_f] = internal
        if settings.jira_plat_cf_package_name:
            base_fields[settings.jira_plat_cf_package_name] = pkg
        if settings.jira_plat_cf_package_vuln_version:
            base_fields[settings.jira_plat_cf_package_vuln_version] = package_vulnerable_version

        dd = _jira_duedate_str(due_date)
        if dd:
            base_fields["duedate"] = dd

        key = self._create_plat_issue_with_organization(
            base_fields,
            organization_refs=organization_refs,
            source_issue_key=source_issue_key,
        )
        self._issue_add_labels_via_update(key, ["CVE"])
        return key

    def _resolve_plat_bug_dev_group(self, source_issue_key: str | None) -> list[dict[str, Any]] | None:
        """Dev Group multi-select: copy list from source issue, else env default(s)."""
        fid = (settings.jira_plat_bug_dev_group_field_id or "").strip()
        if not fid:
            return None
        raw: Any = None
        if settings.jira_plat_bug_dev_group_copy_from_source and (source_issue_key or "").strip():
            try:
                url = f"{self._base}/rest/api/3/issue/{source_issue_key.strip()}"
                r = self._client.get(url, params={"fields": fid})
                r.raise_for_status()
                raw = (r.json().get("fields") or {}).get(fid)
            except Exception:
                raw = None
        return _plat_bug_dev_group_value_list_for_create(
            raw,
            (settings.jira_plat_bug_dev_group_option_value or "").strip(),
        )

    def create_plat_bug(
        self,
        cve_id: str,
        image_basename: str,
        package_name: str,
        package_vulnerable_version: str,
        *,
        priority_name: str | None = None,
        organization_refs: list[dict[str, Any]] | None = None,
        source_issue_key: str | None = None,
        image_display: str | None = None,
        resource_label: str | None = None,
        vendor_fix_version: str | None = None,
        due_date: str | None = None,
    ) -> str:
        """
        Create PLAT Bug: no CVE/package custom fields (per PlainID Bug workflow).
        Description carries image, resource, and vendor version lines.
        """
        summary = f"[{cve_id}] - [{image_basename}]"
        internal = f"{image_basename}_{cve_id}"

        img_line = (image_display or "").strip() or image_basename
        res_line = (resource_label or "").strip() or (package_name or "").strip() or "—"
        desc_plain = _plat_bug_description_text(
            image_display=img_line,
            resource=res_line,
            vendor_affected_version=package_vulnerable_version,
            vendor_fix_version=(vendor_fix_version or "").strip() or "—",
        )

        base_fields: dict[str, Any] = {
            "project": {"key": settings.jira_plat_project_key},
            "summary": summary,
            "description": _text_to_adf(desc_plain),
        }
        if settings.jira_plat_bug_issuetype_id and str(settings.jira_plat_bug_issuetype_id).strip():
            base_fields["issuetype"] = {"id": str(settings.jira_plat_bug_issuetype_id).strip()}
        else:
            base_fields["issuetype"] = {"name": settings.jira_plat_bug_issuetype_name}

        base_fields["labels"] = ["CVE"]

        if priority_name:
            base_fields["priority"] = {"name": priority_name}
        int_f = (settings.jira_plat_cf_internal_id or "").strip()
        org_id_set = _plat_organization_field_id_set()
        if int_f and int_f.casefold() not in org_id_set:
            base_fields[int_f] = internal

        dg_fid = (settings.jira_plat_bug_dev_group_field_id or "").strip()
        if dg_fid:
            dg_val = self._resolve_plat_bug_dev_group(source_issue_key)
            if not dg_val:
                raise RuntimeError(
                    "PLAT Bug requires Dev Group. Set it on the portal source Jira issue, "
                    "or set JIRA_PLAT_BUG_DEV_GROUP_OPTION_VALUE (comma-separated labels allowed)."
                )
            base_fields[dg_fid] = dg_val

        dd = _jira_duedate_str(due_date)
        if dd:
            base_fields["duedate"] = dd

        return self._create_plat_issue_with_organization(
            base_fields,
            organization_refs=organization_refs,
            source_issue_key=source_issue_key,
        )

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

