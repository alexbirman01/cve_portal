"""PLAT Invalid workflow status → N/A fix/tag override."""

from api.app.cve_row_derived import (
    plat_issue_status_invalid_for_keys,
    plat_issue_status_is_invalid,
)


def test_plat_issue_status_is_invalid():
    assert plat_issue_status_is_invalid("Invalid")
    assert plat_issue_status_is_invalid(" invalid ")
    assert not plat_issue_status_is_invalid("")
    assert not plat_issue_status_is_invalid("Open")


def test_plat_issue_status_invalid_for_keys():
    row = {
        "plat_security_field_sync": {
            "PLAT-1": {"issue_status": "Open", "fix_versions": "x"},
            "PLAT-2": {"issue_status": "Invalid", "fix_versions": "y"},
        },
    }
    assert not plat_issue_status_invalid_for_keys(row, ["PLAT-1"])
    assert plat_issue_status_invalid_for_keys(row, ["PLAT-2"])
    assert plat_issue_status_invalid_for_keys(row, ["PLAT-1", "PLAT-2"])
