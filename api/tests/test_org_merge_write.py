"""Organization merge must append, verify what Jira stored, and never silently drop values."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from api.app import jira_client as jc
from api.app.jira_client import JiraClient

FID = "customfield_10727"


@pytest.fixture(autouse=True)
def _org_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jc, "_plat_organization_field_ids", lambda: [FID])
    monkeypatch.setattr(jc.settings, "jira_plat_skip_organization_field_on_create", False)


def _values_in(body: dict[str, Any]) -> list[str] | None:
    """Values of an `update` payload that names organizations by `value` / `name`, else None."""
    v = (body.get("update") or {}).get(FID)
    if not isinstance(v, list) or not v or not all(isinstance(x, dict) for x in v):
        return None
    keys = {"value", "name"}
    if not all(keys & set(x) for x in v):
        return None
    return [str(x.get("value") or x.get("name")) for x in v]


class FakeJira:
    """Minimal Jira double holding one Organization field."""

    def __init__(self, names: list[str]) -> None:
        self.names = list(names)
        self.puts: list[dict[str, Any]] = []

    def get(self, url: str, **_: Any) -> MagicMock:
        r = MagicMock()
        r.raise_for_status.return_value = None
        r.json.return_value = {"fields": {FID: [{"value": n} for n in self.names]}}
        return r

    def store(self, body: dict[str, Any]) -> None:
        values = _values_in(body)
        if values is not None:
            self.names = values

    def put(self, url: str, *, json: dict[str, Any], **_: Any) -> MagicMock:
        self.puts.append(json)
        self.store(json)
        r = MagicMock()
        r.is_success = True
        return r


def _client(fake: FakeJira, wanted: list[str]) -> JiraClient:
    jira = object.__new__(JiraClient)
    jira._base = "https://example.atlassian.net"
    jira._headers = {}
    jira._client = fake
    jira._organization_display_names_for_plat_create = lambda *_a, **_k: list(wanted)  # type: ignore[method-assign]
    return jira


def test_merge_appends_new_org_and_keeps_existing():
    fake = FakeJira(["Humana"])

    assert _client(fake, ["Northern Trust"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is True
    assert fake.names == ["Humana", "Northern Trust"]


def test_merge_skips_write_when_org_already_present():
    fake = FakeJira(["Humana"])

    assert _client(fake, ["humana"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is False
    assert fake.puts == []
    assert fake.names == ["Humana"]


def test_merge_restores_previous_values_when_jira_clears_the_field():
    class PickyJira(FakeJira):
        """Answers 2xx for everything but only stores single-value writes; multi-value clears the field."""

        def store(self, body: dict[str, Any]) -> None:
            values = _values_in(body)
            self.names = values if values is not None and len(values) == 1 else []

    fake = PickyJira(["Humana"])

    with pytest.raises(RuntimeError, match="dropped Organization.*restored"):
        _client(fake, ["Northern Trust"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1")
    assert fake.names == ["Humana"]


def test_merge_reports_failure_when_write_is_ignored():
    class IgnoringJira(FakeJira):
        def store(self, body: dict[str, Any]) -> None:
            return None

    fake = IgnoringJira(["Humana"])

    with pytest.raises(RuntimeError, match="did not store Organization"):
        _client(fake, ["Northern Trust"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1")
    assert fake.names == ["Humana"]


def test_merge_does_not_write_when_current_state_is_unreadable():
    fake = FakeJira(["Humana"])
    fake.get = MagicMock(side_effect=RuntimeError("jira down"))  # type: ignore[method-assign]

    assert _client(fake, ["Northern Trust"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is False
    assert fake.puts == []


def test_merge_skips_when_source_orgs_have_no_display_names():
    fake = FakeJira(["Humana"])

    assert _client(fake, []).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is False
    assert fake.puts == []
