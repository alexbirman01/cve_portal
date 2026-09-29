"""Release code from fix versions, the server-side comment builder, and comment visibility."""

from __future__ import annotations

import datetime as dt
from typing import Any
from unittest.mock import MagicMock

import pytest

from api.app import jira_client as jc
from api.app.customer_status_comment import (
    build_customer_status_comment,
    build_customer_status_comment_intro,
    collect_customer_status_rows,
)
from api.app.cve_row_derived import release_code_from_fix_versions
from api.app.jira_client import JiraClient

REAL_VERSION = "Platform MNG (Q4RC1) - October-11th (5.2642.x)"


# ─── release code extraction ─────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("fix_versions", "expected"),
    [
        (REAL_VERSION, "5.2642.x"),
        ("5.2642.x", "5.2642.x"),
        ("5.2631.2", "5.2631.2"),
        ("CVE pending Version", None),
        ("", None),
        ("None", None),
        # Several versions on one ticket keep their order and dedupe.
        ("A (5.2642.x), B (5.2643.x)", "5.2642.x, 5.2643.x"),
        ("A (5.2642.x), B (5.2642.x)", "5.2642.x"),
    ],
)
def test_release_code_from_fix_versions(fix_versions: str, expected: str | None) -> None:
    assert release_code_from_fix_versions(fix_versions) == expected


# ─── comment intro ───────────────────────────────────────────────────────────

def test_intro_matches_the_requested_wording() -> None:
    assert build_customer_status_comment_intro(dt.date(2026, 9, 29)) == [
        "This CVE report is updated daily.",
        "Last updated: September 29, 2026",
        "",
        'Note: The "Expected Release Date" is an estimate and may be subject to change.',
        "",
    ]


def test_intro_carries_no_marker() -> None:
    """The comment is customer-visible; a marker would be rendered as literal text."""
    assert "CVE-Portal-Customer-Status" not in "\n".join(build_customer_status_comment_intro())


# ─── the table ───────────────────────────────────────────────────────────────

def _row(cve: str, severity: str, score: str, image: str, key: str, fix: str, status: str) -> dict[str, Any]:
    basename = image.split("/")[-1]
    return {
        "cve_id": cve,
        "severity": severity,
        "score": score,
        "affected_images": [{"image": image, "tag": "5.2637.7.2"}],
        "affected_resource": "openssl",
        "plat_security_keys": [key],
        "plat_security_for_images": {basename: [key]},
        "plat_security_field_sync": {
            key: {"fix_versions": fix, "tag_numbers": "", "issue_status": status},
        },
    }


def test_fix_version_and_date_come_from_the_version_name() -> None:
    result = {"cve_rows": [_row("CVE-1", "HIGH", "8.7", "plainid/pip-operator", "PLAT-1", REAL_VERSION, "Waiting for Tag")]}
    row = collect_customer_status_rows(result)[0]
    assert row["fix_version"] == "5.2642.x"
    assert row["expected_release"] == "October 12, 2026"  # Monday of ISO week 42


def test_version_without_a_release_code_reads_in_progress() -> None:
    """Never show the customer a raw version name like 'CVE pending Version'."""
    result = {"cve_rows": [_row("CVE-2", "CRITICAL", "9.1", "plainid/theruntime", "PLAT-2", "CVE pending Version", "pending release")]}
    row = collect_customer_status_rows(result)[0]
    assert row["fix_version"] == "In progress"
    assert row["expected_release"] == "In progress"


def test_rows_sort_most_severe_first() -> None:
    result = {"cve_rows": [
        _row("CVE-LOW", "LOW", "2.0", "plainid/agent", "PLAT-3", REAL_VERSION, "Waiting for Tag"),
        _row("CVE-CRIT", "CRITICAL", "9.9", "plainid/agent", "PLAT-4", REAL_VERSION, "Waiting for Tag"),
    ]}
    assert [r["cve"] for r in collect_customer_status_rows(result)] == ["CVE-CRIT", "CVE-LOW"]


def test_invalid_plat_status_reads_na() -> None:
    result = {"cve_rows": [_row("CVE-3", "HIGH", "7.0", "plainid/agent", "PLAT-5", REAL_VERSION, "Invalid")]}
    row = collect_customer_status_rows(result)[0]
    assert row["expected_release"] == "N/A"
    assert row["fix_version"] == "N/A"


def test_empty_result_still_produces_a_readable_comment() -> None:
    text = build_customer_status_comment({"cve_rows": []}, dt.date(2026, 9, 29))
    assert "No CVE rows to display." in text
    assert text.startswith("This CVE report is updated daily.")


def test_table_is_a_pipe_table_with_the_fixed_columns() -> None:
    result = {"cve_rows": [_row("CVE-4", "HIGH", "8.0", "plainid/agent", "PLAT-6", REAL_VERSION, "Waiting for Tag")]}
    lines = build_customer_status_comment(result).splitlines()
    header = next(ln for ln in lines if ln.startswith("CVE "))
    assert [h.strip() for h in header.split(" | ")] == [
        "CVE", "Severity", "Image", "Package", "Expected release date", "Fix Version",
    ]


# ─── comment visibility + upsert target ──────────────────────────────────────

class _FakeHttp:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.puts: list[tuple[str, dict]] = []

    def get(self, url, **_):
        return _Resp({"comments": [], "total": 0, "startAt": 0, "maxResults": 100})

    def post(self, url, *, json, **_):
        self.posts.append((url, json))
        return _Resp({"id": "10001"})

    def put(self, url, *, json=None, **_):
        self.puts.append((url, json))
        return _Resp({"id": "10001"})


class _Resp:
    def __init__(self, payload: dict) -> None:
        self.is_success = True
        self.status_code = 200
        self.text = ""
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        return None


def _client(fake: _FakeHttp) -> JiraClient:
    jira = object.__new__(JiraClient)
    jira._base = "https://example.atlassian.net"
    jira._headers = {}
    jira._client = fake
    return jira


def test_external_visibility_is_asserted_not_implied() -> None:
    """Omitting the property lets JSM guess; the value must be sent explicitly."""
    fake = _FakeHttp()
    _client(fake).upsert_customer_status_comment("PLATFORM-1", "body", internal=False)
    _, payload = fake.posts[0]
    assert payload["properties"] == [{"key": "sd.public.comment", "value": {"internal": False}}]


def test_internal_visibility_still_available() -> None:
    fake = _FakeHttp()
    _client(fake).upsert_customer_status_comment("PLATFORM-1", "body", internal=True)
    _, payload = fake.posts[0]
    assert payload["properties"] == [{"key": "sd.public.comment", "value": {"internal": True}}]


def test_known_comment_id_updates_in_place_without_listing() -> None:
    fake = _FakeHttp()
    out = _client(fake).upsert_customer_status_comment(
        "PLATFORM-1", "body", internal=False, known_comment_id="10001",
    )
    assert out["action"] == "updated"
    assert fake.posts == []
    assert fake.puts[0][0].endswith("/rest/api/3/issue/PLATFORM-1/comment/10001")


def test_without_a_known_id_it_falls_back_to_the_marker_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Comments posted before the id was stored must be adopted, not duplicated."""
    fake = _FakeHttp()
    jira = _client(fake)
    monkeypatch.setattr(JiraClient, "list_issue_comments", lambda self, key: [{"id": "999"}])
    monkeypatch.setattr(JiraClient, "find_customer_status_comment_id", lambda self, comments: "999")
    out = jira.upsert_customer_status_comment("PLATFORM-1", "body", internal=False)
    assert out["action"] == "updated"
    assert out["comment_id"] == "999"
    assert fake.posts == []


def test_creates_and_reports_the_new_id(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttp()
    jira = _client(fake)
    monkeypatch.setattr(JiraClient, "list_issue_comments", lambda self, key: [])
    monkeypatch.setattr(JiraClient, "find_customer_status_comment_id", lambda self, comments: None)
    out = jira.upsert_customer_status_comment("PLATFORM-1", "body", internal=False)
    assert out["action"] == "created"
    assert out["comment_id"] == "10001"
    assert fake.puts == []
