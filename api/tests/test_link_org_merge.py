"""Tests for Relates link + Organization merge during Link existing PLAT."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from api.app.plat_linking import link_plat_key_to_parent


def _counts() -> dict:
    return {"links_checked": 0, "links_created": 0, "orgs_merged": 0, "errors": []}


def test_link_plat_key_relates_and_merges_org():
    jira = MagicMock()
    jira.ensure_plat_linked_to_parent.return_value = SimpleNamespace(
        created=True,
        error_warning=None,
    )
    jira.merge_organization_on_issue.return_value = True
    counts = _counts()
    seen: set[str] = set()

    link_plat_key_to_parent(jira, "plat-1234", "PLATFORM-2151", seen, counts)

    assert "PLAT-1234" in seen
    jira.ensure_plat_linked_to_parent.assert_called_once_with("PLAT-1234", "PLATFORM-2151")
    jira.merge_organization_on_issue.assert_called_once_with("PLAT-1234", None, "PLATFORM-2151")
    assert counts["links_checked"] == 1
    assert counts["links_created"] == 1
    assert counts["orgs_merged"] == 1
    assert counts["errors"] == []


def test_link_plat_key_org_merge_failure_is_nonfatal():
    jira = MagicMock()
    jira.ensure_plat_linked_to_parent.return_value = SimpleNamespace(
        created=False,
        error_warning=None,
    )
    jira.merge_organization_on_issue.side_effect = RuntimeError("jira down")
    counts = _counts()
    seen: set[str] = set()

    link_plat_key_to_parent(jira, "PLAT-99", "PLATFORM-1", seen, counts)

    assert counts["links_checked"] == 1
    assert counts["links_created"] == 0
    assert counts["orgs_merged"] == 0
    assert counts["errors"] == ["org merge on PLAT-99: jira down"]


def test_link_plat_key_skips_duplicate_keys():
    jira = MagicMock()
    jira.ensure_plat_linked_to_parent.return_value = SimpleNamespace(
        created=True,
        error_warning=None,
    )
    jira.merge_organization_on_issue.return_value = False
    counts = _counts()
    seen: set[str] = set()

    link_plat_key_to_parent(jira, "PLAT-1", "PLATFORM-2", seen, counts)
    link_plat_key_to_parent(jira, "plat-1", "PLATFORM-2", seen, counts)

    assert jira.ensure_plat_linked_to_parent.call_count == 1
    assert jira.merge_organization_on_issue.call_count == 1
    assert counts["links_checked"] == 1
    assert counts["orgs_merged"] == 0
