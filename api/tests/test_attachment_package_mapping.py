"""Attachment packages must reach the row for every id family, and a deleted status
comment must not wedge the ticket."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from api.app.jira_client import JiraClient
from api.app.parsing import canonical_vuln_id_case
from api.app.cve_row_derived import ticket_packages_by_vuln_id as _ticket_pkgs


# ─── the regression ──────────────────────────────────────────────────────────

def test_sonatype_package_is_reachable_by_its_finding_id() -> None:
    """Keying with .upper() lost every Sonatype package: ids are canonically lowercase."""
    atts = [{"packages": [
        {"cve_id": "sonatype-2025-000535", "package_name": "com.google.code.gson:gson"},
    ]}]
    pkgs = _ticket_pkgs(atts)
    assert pkgs.get("sonatype-2025-000535") is not None
    assert pkgs["sonatype-2025-000535"][0]["product"] == "com.google.code.gson:gson"


@pytest.mark.parametrize(
    ("parsed_id", "finding_id"),
    [
        ("sonatype-2025-000535", "sonatype-2025-000535"),
        ("SONATYPE-2025-000535", "sonatype-2025-000535"),
        ("cve-2026-12185", "CVE-2026-12185"),
        ("CVE-2026-12185", "CVE-2026-12185"),
        ("ghsa-hrxh-6v49-42gf", "GHSA-HRXH-6V49-42GF"),
    ],
)
def test_lookup_survives_case_differences(parsed_id: str, finding_id: str) -> None:
    pkgs = _ticket_pkgs([{"packages": [{"cve_id": parsed_id, "package_name": "pkg"}]}])
    assert pkgs.get(canonical_vuln_id_case(finding_id)) is not None


def test_cve_and_sonatype_packages_coexist() -> None:
    pkgs = _ticket_pkgs([{"packages": [
        {"cve_id": "CVE-2026-12185", "package_name": "org.bouncycastle:bcprov-jdk18on"},
        {"cve_id": "sonatype-2026-006746", "package_name": "org.apache.logging.log4j:log4j-core"},
    ]}])
    assert set(pkgs) == {"CVE-2026-12185", "sonatype-2026-006746"}


# ─── deleted status comment ──────────────────────────────────────────────────

class _FakeHttp:
    """`missing` ids answer 404 on PUT, as Jira does for a deleted comment."""

    def __init__(self, missing: set[str] | None = None) -> None:
        self.missing = missing or set()
        self.posts: list[str] = []
        self.puts: list[str] = []

    def get(self, url, **_):
        return _Resp(200, {"comments": [], "total": 0, "startAt": 0, "maxResults": 100})

    def post(self, url, *, json, **_):
        self.posts.append(url)
        return _Resp(200, {"id": "999"})

    def put(self, url, *, json=None, **_):
        self.puts.append(url)
        cid = url.rstrip("/").split("/")[-1]
        return _Resp(404 if cid in self.missing else 200, {"id": cid})


class _Resp:
    def __init__(self, status: int, payload: dict) -> None:
        self.status_code = status
        self.is_success = status < 400
        self.text = "Can not find a comment" if status == 404 else ""
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=self)  # type: ignore[arg-type]


def _client(fake: _FakeHttp) -> JiraClient:
    jira = object.__new__(JiraClient)
    jira._base = "https://example.atlassian.net"
    jira._headers = {}
    jira._client = fake
    return jira


def test_deleted_comment_is_recreated_instead_of_wedging_the_ticket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PLATFORM-2350: a stored id whose comment was deleted 404s forever without this."""
    fake = _FakeHttp(missing={"284920"})
    monkeypatch.setattr(JiraClient, "find_customer_status_comment_id", lambda self, c: None)
    out = _client(fake).upsert_customer_status_comment(
        "PLATFORM-2350", "body", internal=False, known_comment_id="284920",
    )
    assert out["action"] == "created"
    assert out["comment_id"] == "999"   # caller persists this, so recovery is permanent
    assert fake.posts, "expected a fresh comment to be posted"


def test_live_comment_is_still_updated_in_place() -> None:
    fake = _FakeHttp()
    out = _client(fake).upsert_customer_status_comment(
        "PLATFORM-2350", "body", internal=False, known_comment_id="284920",
    )
    assert out["action"] == "updated"
    assert out["comment_id"] == "284920"
    assert fake.posts == []


def test_non_404_errors_still_surface() -> None:
    """Only 'the comment is gone' may fall through; real failures must not be swallowed."""
    class _ServerError(_FakeHttp):
        def put(self, url, *, json=None, **_):
            self.puts.append(url)
            return _Resp(500, {})

    fake = _ServerError()
    with pytest.raises(httpx.HTTPStatusError):
        _client(fake).upsert_customer_status_comment(
            "PLATFORM-2350", "body", internal=False, known_comment_id="284920",
        )
    assert fake.posts == []


# ─── package name from PLAT sync ─────────────────────────────────────────────

from api.app.cve_row_derived import apply_plat_vendor_fields_from_sync  # noqa: E402


def _synced_row(**entry: Any) -> dict[str, Any]:
    return {
        "cve_id": "sonatype-2025-000535",
        "plat_security_keys": ["PLAT-32379"],
        "plat_security_for_images": {"theruntime": ["PLAT-32379"]},
        "affected_images": [{"image": "theruntime", "tag": "5.2637.7.2"}],
        "plat_security_field_sync": {"PLAT-32379": entry},
    }


def test_package_name_is_taken_from_the_plat_ticket() -> None:
    """PLATFORM-2350: sync read 'gson' from Jira but never put it on the row."""
    row = _synced_row(package_name="gson", package_vuln_version="2.13.1")
    apply_plat_vendor_fields_from_sync(row)
    assert row["affected_resource"] == "gson"
    assert row["affected_version"] == "2.13.1"


def test_a_hand_corrected_name_in_jira_wins() -> None:
    row = _synced_row(package_name="corrected-name")
    row["affected_resource"] = "com.google.code.gson:gson"
    apply_plat_vendor_fields_from_sync(row)
    assert row["affected_resource"] == "corrected-name"


@pytest.mark.parametrize("empty", ["", "None", "none", None])
def test_an_empty_jira_name_leaves_the_scan_file_value_alone(empty) -> None:
    row = _synced_row(package_name=empty)
    row["affected_resource"] = "com.google.code.gson:gson"
    apply_plat_vendor_fields_from_sync(row)
    assert row["affected_resource"] == "com.google.code.gson:gson"


def test_no_sync_data_changes_nothing() -> None:
    row = {"cve_id": "CVE-1", "affected_resource": "openssl"}
    apply_plat_vendor_fields_from_sync(row)
    assert row["affected_resource"] == "openssl"
