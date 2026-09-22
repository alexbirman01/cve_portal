"""Affected tags: scan-tag normalization, per-image lookup, and the add-only Jira write."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from api.app import jira_client as jc
from api.app.cve_row_derived import affected_tag_for_basename, normalize_affected_tag
from api.app.jira_client import JiraClient

FID = "customfield_11577"


# ---------------------------------------------------------------------------
# normalize_affected_tag
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("5.2635.5", "5.2635.5"),
        ("  5.2635.5  ", "5.2635.5"),
        ("plainid/paa:5.2635.5", "5.2635.5"),
        ("docker.io/plainid/agent:5.2635.5", "5.2635.5"),
        # Aqua transactional tag {version}_{Service}_{suffix} reduces to the bare version.
        ("5.2635.5_pip_operator_15Jun2026", "5.2635.5"),
        ("", None),
        (None, None),
        ("NA", None),
        ("n/a", None),
        ("latest", None),
        # Jira labels fields reject whitespace — skipped rather than mangled.
        ("5.2635.5 hotfix", None),
        ("plainid/paa:", None),
    ],
)
def test_normalize_affected_tag(raw: Any, expected: str | None) -> None:
    assert normalize_affected_tag(raw) == expected


# ---------------------------------------------------------------------------
# affected_tag_for_basename
# ---------------------------------------------------------------------------

def test_tag_for_basename_picks_the_matching_image() -> None:
    row = {
        "affected_images": [
            {"image": "plainid/paa", "tag": "5.2635.5"},
            {"image": "plainid/secrets-mgmt", "tag": "5.2640.1"},
        ]
    }
    assert affected_tag_for_basename(row, "paa") == "5.2635.5"
    assert affected_tag_for_basename(row, "secrets-mgmt") == "5.2640.1"


def test_tag_for_basename_is_case_insensitive() -> None:
    row = {"affected_images": [{"image": "plainid/PAA", "tag": "5.2635.5"}]}
    assert affected_tag_for_basename(row, "paa") == "5.2635.5"


def test_tag_for_basename_falls_back_to_legacy_fields() -> None:
    row = {"affected_image": "plainid/paa", "affected_tag": "5.2635.5"}
    assert affected_tag_for_basename(row, "paa") == "5.2635.5"


def test_tag_for_basename_unknown_image_or_missing_tag() -> None:
    row = {"affected_images": [{"image": "plainid/paa", "tag": "5.2635.5"}]}
    assert affected_tag_for_basename(row, "agent") is None
    assert affected_tag_for_basename({"affected_images": [{"image": "plainid/paa", "tag": ""}]}, "paa") is None
    assert affected_tag_for_basename({}, "paa") is None


# ---------------------------------------------------------------------------
# JiraClient.add_affected_tags
# ---------------------------------------------------------------------------

class FakeJira:
    """Records PUTs; `fail_v3` makes the REST v3 URL fail so the v2 fallback is exercised."""

    def __init__(self, *, fail_v3: bool = False, fail_all: bool = False) -> None:
        self.fail_v3 = fail_v3
        self.fail_all = fail_all
        self.puts: list[tuple[str, dict[str, Any]]] = []

    def put(self, url: str, *, json: dict[str, Any], **_: Any) -> MagicMock:
        self.puts.append((url, json))
        r = MagicMock()
        r.is_success = not (self.fail_all or (self.fail_v3 and "/rest/api/3/" in url))
        r.text = "field not on screen"
        return r


def _client(fake: FakeJira) -> JiraClient:
    jira = object.__new__(JiraClient)
    jira._base = "https://example.atlassian.net"
    jira._headers = {}
    jira._client = fake
    return jira


@pytest.fixture(autouse=True)
def _affected_tags_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jc.settings, "jira_plat_cf_affected_tags_field_id", FID)


def test_add_affected_tags_sends_add_ops() -> None:
    fake = FakeJira()
    _client(fake).add_affected_tags("PLAT-32033", ["5.2635.5"])
    url, body = fake.puts[0]
    assert url.endswith("/rest/api/3/issue/PLAT-32033")
    assert body == {"update": {FID: [{"add": "5.2635.5"}]}}


def test_add_affected_tags_falls_back_to_v2() -> None:
    fake = FakeJira(fail_v3=True)
    _client(fake).add_affected_tags("PLAT-32033", ["5.2635.5"])
    assert [u for u, _ in fake.puts] == [
        "https://example.atlassian.net/rest/api/3/issue/PLAT-32033",
        "https://example.atlassian.net/rest/api/2/issue/PLAT-32033",
    ]


def test_add_affected_tags_raises_when_both_fail() -> None:
    fake = FakeJira(fail_all=True)
    with pytest.raises(RuntimeError, match="PLAT-32033"):
        _client(fake).add_affected_tags("PLAT-32033", ["5.2635.5"])


def test_add_affected_tags_noop_without_tags_or_key() -> None:
    fake = FakeJira()
    client = _client(fake)
    client.add_affected_tags("PLAT-32033", [])
    client.add_affected_tags("PLAT-32033", ["", "  "])
    client.add_affected_tags("", ["5.2635.5"])
    assert fake.puts == []


def test_add_affected_tags_disabled_when_field_id_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jc.settings, "jira_plat_cf_affected_tags_field_id", "")
    fake = FakeJira()
    _client(fake).add_affected_tags("PLAT-32033", ["5.2635.5"])
    assert fake.puts == []
