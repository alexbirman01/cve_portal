"""Organization merge: option resolution, add-only write, verify, and failfast."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from api.app import jira_client as jc
from api.app.jira_client import JiraClient, _norm_org_name

FID = "customfield_10727"

# Minimal allowedValues for the field (id, value pairs).
_OPTIONS = [
    {"id": "10950", "value": "Humana"},
    {"id": "10922", "value": "EYGlobal"},
    {"id": "10951", "value": "Northern Trust"},
]


@pytest.fixture(autouse=True)
def _org_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jc, "_plat_organization_field_ids", lambda: [FID])
    monkeypatch.setattr(jc.settings, "jira_plat_skip_organization_field_on_create", False)
    monkeypatch.setattr(jc.settings, "jira_plat_organization_name_aliases", "")


def _add_ids_in(body: dict[str, Any]) -> list[str] | None:
    """Ids from an `update.add` payload, else None."""
    ops = (body.get("update") or {}).get(FID)
    if not isinstance(ops, list) or not ops:
        return None
    if not all(isinstance(x, dict) and "add" in x for x in ops):
        return None
    return [str(x["add"].get("id", "")) for x in ops]


class FakeJira:
    """Minimal Jira double with an Organization field backed by allowedValues option ids."""

    def __init__(self, stored_ids: list[str]) -> None:
        self.stored_ids: list[str] = list(stored_ids)
        self.puts: list[dict[str, Any]] = []

    def _option(self, opt_id: str) -> dict[str, Any] | None:
        return next((o for o in _OPTIONS if o["id"] == opt_id), None)

    def get(self, url: str, **_: Any) -> MagicMock:
        r = MagicMock()
        r.raise_for_status.return_value = None
        if "editmeta" in url:
            r.json.return_value = {
                "fields": {
                    FID: {
                        "operations": ["add", "set", "remove"],
                        "allowedValues": _OPTIONS,
                    }
                }
            }
        else:
            # Issue field GET — return stored options with id + value.
            field_val = [
                {"id": oid, "value": (self._option(oid) or {}).get("value", oid)}
                for oid in self.stored_ids
                if oid
            ]
            r.json.return_value = {"fields": {FID: field_val}}
        return r

    def put(self, url: str, *, json: dict[str, Any], **_: Any) -> MagicMock:
        self.puts.append(json)
        ids = _add_ids_in(json)
        if ids is not None:
            for oid in ids:
                if oid and oid not in self.stored_ids:
                    self.stored_ids.append(oid)
        r = MagicMock()
        r.is_success = True
        return r


def _client(fake: FakeJira, wanted: list[str]) -> JiraClient:
    jira = object.__new__(JiraClient)
    jira._base = "https://example.atlassian.net"
    jira._headers = {}
    jira._client = fake
    jira._org_option_cache = None
    jira._jsm_orgs_cache = None
    jira._source_org_refs_cache = {}
    jira._plat_search_cache = {}
    jira._unresolvable_org_norms = set()
    jira._organization_display_names_for_plat_create = lambda *_a, **_k: list(wanted)  # type: ignore[method-assign]
    return jira


# ---------------------------------------------------------------------------
# _norm_org_name
# ---------------------------------------------------------------------------

def test_norm_strips_nonalpha_and_casefolds() -> None:
    assert _norm_org_name("EY Global") == "eyglobal"
    assert _norm_org_name("EYGlobal") == "eyglobal"
    assert _norm_org_name("Ernst & Young, Inc.") == "ernstyounginc"
    assert _norm_org_name("Northern Trust") == "northerntrust"


# ---------------------------------------------------------------------------
# Option resolution
# ---------------------------------------------------------------------------

def test_resolve_exact_match() -> None:
    """Exact casefold match resolves to the correct option id."""
    fake = FakeJira([])
    client = _client(fake, ["Humana"])
    assert client.merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is True
    ids = _add_ids_in(fake.puts[0])
    assert ids == ["10950"]


def test_resolve_normalized_match_ey_global() -> None:
    """'EY Global' normalises to 'eyglobal' and resolves to the 'EYGlobal' option."""
    fake = FakeJira([])
    client = _client(fake, ["EY Global"])
    assert client.merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is True
    ids = _add_ids_in(fake.puts[0])
    assert ids == ["10922"]  # EYGlobal


def test_unresolvable_name_raises_with_details() -> None:
    fake = FakeJira([])
    client = _client(fake, ["Completely Unknown Co"])
    with pytest.raises(RuntimeError, match="Completely Unknown Co"):
        client.merge_organization_on_issue("PLAT-1", None, "PLATFORM-1")
    assert fake.puts == []  # no write attempted


def test_unresolvable_name_skips_on_subsequent_tickets() -> None:
    """After the first failure the client remembers the bad name and returns False on next call."""
    fake = FakeJira([])
    client = _client(fake, ["Completely Unknown Co"])
    with pytest.raises(RuntimeError):
        client.merge_organization_on_issue("PLAT-1", None, "PLATFORM-1")
    # Second ticket: same client instance, same bad name — must return False without PUT.
    fake2 = FakeJira([])
    client._client = fake2  # type: ignore[assignment]
    result = client.merge_organization_on_issue("PLAT-2", None, "PLATFORM-1")
    assert result is False
    assert fake2.puts == []


# ---------------------------------------------------------------------------
# Add payload shape
# ---------------------------------------------------------------------------

def test_put_uses_add_operation_not_full_list() -> None:
    """Exactly one PUT with the `add` operation; no full-list set."""
    fake = FakeJira([])
    _client(fake, ["Northern Trust"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1")
    assert len(fake.puts) == 1
    body = fake.puts[0]
    ops = (body.get("update") or {}).get(FID)
    assert ops is not None
    assert all("add" in op for op in ops), "Expected only `add` operations, got set/full-list"


def test_appends_new_org_and_keeps_existing() -> None:
    fake = FakeJira(["10950"])  # Humana already stored
    client = _client(fake, ["Northern Trust"])
    assert client.merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is True
    assert "10950" in fake.stored_ids
    assert "10951" in fake.stored_ids


# ---------------------------------------------------------------------------
# Skip when already present
# ---------------------------------------------------------------------------

def test_skips_write_when_option_already_present_by_id() -> None:
    fake = FakeJira(["10922"])  # EYGlobal already stored by id
    client = _client(fake, ["EY Global"])  # normalises to the same option
    assert client.merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is False
    assert fake.puts == []


def test_skips_write_when_source_orgs_empty() -> None:
    fake = FakeJira([])
    assert _client(fake, []).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1") is False
    assert fake.puts == []


def test_skips_write_when_current_state_unreadable() -> None:
    fake = FakeJira([])
    fake.get = MagicMock(side_effect=RuntimeError("jira down"))  # type: ignore[method-assign]
    # editmeta GET also fails → option map empty → RuntimeError from empty option_map check
    # (The unreadable current-state path returns False only when editmeta succeeds but GET fails later.)
    with pytest.raises(RuntimeError):
        _client(fake, ["Humana"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1")


# ---------------------------------------------------------------------------
# Verify after write
# ---------------------------------------------------------------------------

def test_raises_when_jira_ignores_the_add() -> None:
    """If Jira answers 2xx but doesn't store the value, RuntimeError is raised."""

    class IgnoringJira(FakeJira):
        def put(self, url: str, *, json: dict[str, Any], **_: Any) -> MagicMock:
            self.puts.append(json)
            r = MagicMock()
            r.is_success = True
            return r  # stored_ids unchanged

    fake = IgnoringJira(["10950"])  # Humana already there; want to add Northern Trust
    with pytest.raises(RuntimeError, match="did not store"):
        _client(fake, ["Northern Trust"]).merge_organization_on_issue("PLAT-1", None, "PLATFORM-1")
    # Original values must still be present (add never removed Humana).
    assert "10950" in fake.stored_ids
