"""Sonatype/Nexus IQ JSON report: image/tag lift, severity map, non-CVE ids, PLAT search."""

from __future__ import annotations

import json
import os

import pytest

from api.app.parsing import (
    is_cve_id,
    is_ghsa_id,
    is_sonatype_id,
    normalize_vuln_id,
    parse_attachment_bytes,
    sonatype_image_tag_from_pathnames,
    sonatype_severity_from_threat,
)
from api.app.plat_cve_match import (
    image_basename_from_correlation,
    image_basename_from_summary,
    is_sonatype_vuln_id,
    jql_plat_vuln_id_clause,
)

CVE_CFN = 11245
INTERNAL_CFN = 10744

REAL_REPORT = "/Users/alexbirman/Downloads/response_1790089175374.json"


# ─── image / tag from pathnames ──────────────────────────────────────────────

def test_image_and_tag_lifted_from_pathname() -> None:
    paths = [
        "plainid-theruntime_5.2637.7.2.tar/f882aff/layer.tar/app/theruntime.jar/META-INF/pom.xml"
    ]
    assert sonatype_image_tag_from_pathnames(paths) == ("theruntime", "5.2637.7.2")


def test_plainid_prefix_is_stripped_only_as_prefix() -> None:
    assert sonatype_image_tag_from_pathnames(["plainid-agent_1.2.3.tar/x"]) == ("agent", "1.2.3")
    # No prefix to strip — the name stands on its own.
    assert sonatype_image_tag_from_pathnames(["theruntime_1.2.3.tar/x"]) == ("theruntime", "1.2.3")


def test_pathnames_without_archive_prefix_yield_nothing() -> None:
    assert sonatype_image_tag_from_pathnames(["app/lib/foo.jar"]) is None
    assert sonatype_image_tag_from_pathnames([]) is None
    assert sonatype_image_tag_from_pathnames(["plainid-theruntime.tar/x"]) is None


def test_first_matching_pathname_wins() -> None:
    paths = ["app/lib/foo.jar", "plainid-pdp_9.9.9.tar/layer.tar/x"]
    assert sonatype_image_tag_from_pathnames(paths) == ("pdp", "9.9.9")


# ─── threatCategory → severity ───────────────────────────────────────────────

@pytest.mark.parametrize(
    ("threat", "expected"),
    [
        ("critical", "CRITICAL"),
        ("severe", "HIGH"),  # Sonatype's band for 7.0-8.9; not a label used elsewhere
        ("moderate", "MEDIUM"),
        ("low", "LOW"),
        ("CRITICAL", "CRITICAL"),
        ("none", None),
        ("", None),
        (None, None),
        ("bogus", None),
    ],
)
def test_severity_from_threat_category(threat, expected) -> None:
    assert sonatype_severity_from_threat(threat) == expected


# ─── id model ────────────────────────────────────────────────────────────────

def test_sonatype_ids_keep_lowercase_while_cve_and_ghsa_uppercase() -> None:
    assert normalize_vuln_id("sonatype-2026-005959") == "sonatype-2026-005959"
    assert normalize_vuln_id("SONATYPE-2026-005959") == "sonatype-2026-005959"
    assert normalize_vuln_id("cve-2026-12185") == "CVE-2026-12185"
    assert normalize_vuln_id("ghsa-hrxh-6v49-42gf") == "GHSA-HRXH-6V49-42GF"


def test_id_predicates_are_mutually_exclusive() -> None:
    assert is_sonatype_id("sonatype-2026-005959")
    assert not is_cve_id("sonatype-2026-005959")
    assert not is_ghsa_id("sonatype-2026-005959")
    assert not is_sonatype_id("CVE-2026-12185")
    assert normalize_vuln_id("sonatype-bogus") is None


# ─── parser ──────────────────────────────────────────────────────────────────

def _report(components: list[dict]) -> bytes:
    return json.dumps({
        "components": components,
        "matchSummary": {"totalComponentCount": len(components)},
        "globalInformation": {"dataVersionDate": None},
    }).encode()


def _component(artifact: str, version: str, issues: list[dict]) -> dict:
    return {
        "pathnames": [f"plainid-theruntime_5.2637.7.2.tar/layer.tar/app/{artifact}.jar"],
        "componentIdentifier": {
            "format": "maven",
            "coordinates": {"groupId": "io.micrometer", "artifactId": artifact, "version": version},
        },
        "securityData": {"securityIssues": issues},
    }


def _parse(data: bytes):
    return parse_attachment_bytes(
        attachment_id="a1", filename="report.json", mime_type="application/json",
        data=data, alias_map={"theruntime": "theruntime"},
    )


def test_parses_facts_with_image_and_tag() -> None:
    data = _report([
        _component("micrometer-core", "1.12.13", [
            {"reference": "CVE-2026-40984", "severity": 8.7, "threatCategory": "severe"},
            {"reference": "sonatype-2026-006465", "severity": 8.2, "threatCategory": "critical"},
        ]),
    ])
    r = _parse(data)
    assert r.status == "ok"
    assert {f.image for f in r.cve_image_facts} == {"theruntime"}
    assert {f.tag for f in r.cve_image_facts} == {"5.2637.7.2"}
    by_id = {f.cve_id: f for f in r.cve_image_facts}
    assert by_id["CVE-2026-40984"].severity == "HIGH"
    assert by_id["CVE-2026-40984"].score == "8.7"
    assert by_id["sonatype-2026-006465"].severity == "CRITICAL"


def test_sonatype_id_is_a_first_class_finding() -> None:
    data = _report([
        _component("micrometer-core", "1.12.13", [
            {"reference": "sonatype-2026-005959", "severity": 8.7, "threatCategory": "severe"},
        ]),
    ])
    r = _parse(data)
    assert [f.cve_id for f in r.cve_image_facts] == ["sonatype-2026-005959"]
    assert r.packages[0].package_name == "io.micrometer:micrometer-core"
    assert r.packages[0].fixed_version is None


def test_every_affected_version_of_an_artifact_is_kept() -> None:
    """One advisory across three versions must not collapse to whichever parsed first."""
    issue = {"reference": "CVE-2026-59296", "severity": 6.3, "threatCategory": "moderate"}
    data = _report([
        _component("micrometer-core", "1.12.13", [issue]),
        _component("micrometer-core", "1.17.0", [issue]),
        _component("micrometer-core", "1.5.10", [issue]),
    ])
    r = _parse(data)
    # One image+tag, so one fact; but all three versions survive as packages.
    assert len(r.cve_image_facts) == 1
    assert sorted(p.package_version for p in r.packages) == ["1.12.13", "1.17.0", "1.5.10"]


def test_unrecognized_advisory_ids_are_skipped_and_counted() -> None:
    data = _report([
        _component("micrometer-core", "1.12.13", [
            {"reference": "CVE-2026-40984", "severity": 8.7, "threatCategory": "severe"},
            {"reference": "whatever-123", "severity": 1.0, "threatCategory": "low"},
        ]),
    ])
    r = _parse(data)
    assert [f.cve_id for f in r.cve_image_facts] == ["CVE-2026-40984"]
    assert "1 unrecognized advisory id(s) skipped" in (r.text_preview or "")


def test_components_without_a_resolvable_image_are_skipped() -> None:
    data = _report([{
        "pathnames": ["app/lib/foo.jar"],
        "componentIdentifier": {"coordinates": {"groupId": "g", "artifactId": "a", "version": "1"}},
        "securityData": {"securityIssues": [{"reference": "CVE-2026-40984", "threatCategory": "severe"}]},
    }])
    assert _parse(data).status == "unparsed"


def test_alias_map_resolves_the_image() -> None:
    data = _report([
        _component("micrometer-core", "1.0.0", [
            {"reference": "CVE-2026-40984", "threatCategory": "severe"},
        ]),
    ])
    r = parse_attachment_bytes(
        attachment_id="a1", filename="report.json", mime_type="application/json",
        data=data, alias_map={"theruntime": "pdp"},
    )
    assert {f.image for f in r.cve_image_facts} == {"pdp"}


# ─── dispatch ────────────────────────────────────────────────────────────────

def test_aqua_json_shape_still_routes_to_the_aqua_parser() -> None:
    aqua = json.dumps([{
        "image_name": "registry/plainid/theruntime:1.2.3",
        "results": {"resources": [{
            "resource": {"name": "openssl", "version": "1.1.1"},
            "vulnerabilities": [{"name": "CVE-2026-12185", "aqua_severity": "high"}],
        }]},
    }]).encode()
    r = _parse(aqua)
    assert r.status == "ok"
    assert [f.cve_id for f in r.cve_image_facts] == ["CVE-2026-12185"]


def test_unrelated_json_is_unparsed() -> None:
    assert _parse(json.dumps({"hello": "world"}).encode()).status == "unparsed"


def test_malformed_json_is_an_error_not_a_crash() -> None:
    assert _parse(b"{not json").status == "error"


# ─── PLAT search / correlation round-trip ────────────────────────────────────

def test_sonatype_searches_the_correlation_field_not_the_cve_field() -> None:
    """The CVE field holds a shared placeholder, so it cannot identify an advisory."""
    clause = jql_plat_vuln_id_clause("sonatype-2026-005959", CVE_CFN, INTERNAL_CFN)
    assert clause == f'cf[{INTERNAL_CFN}] ~ "sonatype-2026-005959"'


def test_cve_and_ghsa_still_search_the_cve_field() -> None:
    assert jql_plat_vuln_id_clause("CVE-2026-12185", CVE_CFN, INTERNAL_CFN) == (
        f'cf[{CVE_CFN}] = "CVE-2026-12185"'
    )
    assert jql_plat_vuln_id_clause("GHSA-HRXH-6V49-42GF", CVE_CFN, INTERNAL_CFN) == (
        f'cf[{CVE_CFN}] IN ("GHSA-HRXH-6V49-42GF", "GHSA-hrxh-6v49-42gf")'
    )


def test_sonatype_predicate() -> None:
    assert is_sonatype_vuln_id("sonatype-2026-005959")
    assert not is_sonatype_vuln_id("CVE-2026-12185")


def test_sonatype_summary_and_correlation_round_trip() -> None:
    """Matches the hand-made reference ticket PLAT-32374."""
    vid = "sonatype-2026-005959"
    assert image_basename_from_summary(f"[{vid}] - [theruntime]", vid) == "theruntime"
    assert image_basename_from_correlation(f"theruntime_{vid}", vid) == "theruntime"


# ─── real report (skipped when the file is absent) ───────────────────────────

@pytest.mark.skipif(not os.path.exists(REAL_REPORT), reason="real Sonatype report not present")
def test_real_report_yields_both_id_families() -> None:
    with open(REAL_REPORT, "rb") as fh:
        r = _parse(fh.read())
    assert r.status == "ok"
    sonatype = [f for f in r.cve_image_facts if is_sonatype_id(f.cve_id)]
    cves = [f for f in r.cve_image_facts if is_cve_id(f.cve_id)]
    assert len(cves) == 43
    assert len(sonatype) == 18
    assert {f.image for f in r.cve_image_facts} == {"theruntime"}
    assert {f.tag for f in r.cve_image_facts} == {"5.2637.7.2"}


# ─── PLAT create payload (pins the PLAT-32374 convention) ────────────────────

class _FakeHttp:
    def __init__(self) -> None:
        self.posts: list[dict] = []

    def post(self, url, *, json, **_):
        self.posts.append(json)
        r = _Resp(True)
        r._payload = {"key": "PLAT-99999"}
        return r

    def put(self, url, *, json=None, **_):
        return _Resp(True)


class _Resp:
    def __init__(self, ok: bool) -> None:
        self.is_success = ok
        self.status_code = 200 if ok else 500
        self.text = ""
        self._payload: dict = {}

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        return None


def _jira_for_create(fake: _FakeHttp):
    from api.app.jira_client import JiraClient

    jira = object.__new__(JiraClient)
    jira._base = "https://example.atlassian.net"
    jira._headers = {}
    jira._client = fake
    jira._organization_ids_for_plat_create = lambda *a, **k: []
    jira._organization_display_names_for_plat_create = lambda *a, **k: []
    return jira


@pytest.fixture
def _skip_org(monkeypatch: pytest.MonkeyPatch):
    from api.app import jira_client as jc

    monkeypatch.setattr(jc.settings, "jira_plat_skip_organization_field_on_create", True)
    monkeypatch.setattr(jc.settings, "jira_plat_cf_account_id", None)
    monkeypatch.setattr(jc.settings, "jira_plat_cf_team_value", None)
    return jc


def test_sonatype_create_matches_reference_ticket(_skip_org) -> None:
    """PLAT-32374: summary, correlation id, and the placeholder CVE ID."""
    fake = _FakeHttp()
    _jira_for_create(fake).create_plat_security_vulnerability(
        "sonatype-2026-005959", "theruntime",
        "com.fasterxml.jackson.core:jackson-databind", "2.22.1",
    )
    f = fake.posts[0]["fields"]
    assert f["summary"] == "[sonatype-2026-005959] - [theruntime]"
    assert f[_skip_org.settings.jira_plat_cf_internal_id] == "theruntime_sonatype-2026-005959"
    assert f[_skip_org.settings.jira_plat_cf_cve_id] == "CVE-0000-00000"
    assert f[_skip_org.settings.jira_plat_cf_package_name] == "com.fasterxml.jackson.core:jackson-databind"
    assert f[_skip_org.settings.jira_plat_cf_package_vuln_version] == "2.22.1"


def test_cve_create_still_puts_the_real_id_in_the_cve_field(_skip_org) -> None:
    fake = _FakeHttp()
    _jira_for_create(fake).create_plat_security_vulnerability(
        "CVE-2026-12185", "theruntime", "openssl", "3.5.7",
    )
    f = fake.posts[0]["fields"]
    assert f["summary"] == "[CVE-2026-12185] - [theruntime]"
    assert f[_skip_org.settings.jira_plat_cf_cve_id] == "CVE-2026-12185"
