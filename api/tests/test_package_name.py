"""Unit tests for canonical_single_package_name."""

from __future__ import annotations

from api.app.package_name import canonical_single_package_name


def test_single_name_unchanged():
    assert canonical_single_package_name("openssl") == "openssl"


def test_comma_separated_takes_first():
    assert canonical_single_package_name("libssl3,libcrypto3") == "libssl3"


def test_semicolon_separated_takes_first():
    assert canonical_single_package_name("libssl3; libcrypto3") == "libssl3"


def test_whitespace_trimmed():
    assert canonical_single_package_name("  libssl3 , libcrypto3  ") == "libssl3"


def test_empty_and_none():
    assert canonical_single_package_name("") is None
    assert canonical_single_package_name("   ") is None
    assert canonical_single_package_name(None) is None


def test_plat_jira_package_name_comma_separated():
    from api.app.cve_row_derived import plat_jira_package_name_for_row

    row = {
        "cve_id": "CVE-2026-34182",
        "affected_resource": "libssl3,libcrypto3",
        "affected_images": [{"image": "plainid/pip-operator", "tag": "5.2617.3"}],
    }
    assert plat_jira_package_name_for_row(row, "pip-operator") == "libssl3"
    assert plat_jira_package_name_for_row(row) == "libssl3"
