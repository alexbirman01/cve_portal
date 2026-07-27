"""PLAT GHSA case-insensitive lookup helpers."""

from api.app.plat_cve_match import (
    image_basename_from_correlation,
    image_basename_from_summary,
    jql_cve_field_equals,
    vuln_id_search_variants,
)


def test_vuln_id_search_variants_ghsa_includes_both_casings():
    variants = vuln_id_search_variants("GHSA-HRXH-6V49-42GF")
    assert variants == ["GHSA-HRXH-6V49-42GF", "GHSA-hrxh-6v49-42gf"]


def test_vuln_id_search_variants_cve_keeps_as_provided():
    assert vuln_id_search_variants("CVE-2024-1234") == ["CVE-2024-1234"]


def test_jql_cve_field_equals_ghsa_uses_in():
    clause = jql_cve_field_equals("GHSA-HRXH-6V49-42GF", 11245)
    assert clause == (
        'cf[11245] IN ("GHSA-HRXH-6V49-42GF", "GHSA-hrxh-6v49-42gf")'
    )


def test_jql_cve_field_equals_cve_uses_eq():
    assert jql_cve_field_equals("CVE-2024-1234", 11245) == 'cf[11245] = "CVE-2024-1234"'


def test_summary_match_lowercase_ghsa_against_upper_search():
    summary = "[GHSA-hrxh-6v49-42gf] - [authz-sql-pdp-modifier]"
    assert (
        image_basename_from_summary(summary, "GHSA-HRXH-6V49-42GF")
        == "authz-sql-pdp-modifier"
    )


def test_correlation_match_lowercase_ghsa_against_upper_search():
    corr = "authz-sql-pdp-modifier_GHSA-hrxh-6v49-42gf"
    assert (
        image_basename_from_correlation(corr, "GHSA-HRXH-6V49-42GF")
        == "authz-sql-pdp-modifier"
    )
