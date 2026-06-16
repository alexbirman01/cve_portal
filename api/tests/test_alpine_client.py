"""Unit tests for Alpine OSV package enrichment."""

from __future__ import annotations

from api.app.alpine_client import AlpineClient, parse_osv_alpine_packages

OSV_OPENSSL_SAMPLE = {
    "affected": [
        {
            "package": {"ecosystem": "Alpine", "name": "openssl"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.5.7-r0"}],
                }
            ],
        },
        {
            "package": {"ecosystem": "Alpine", "name": "openssl"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.5.7-r0"}],
                }
            ],
        },
    ],
}


def test_parse_osv_alpine_openssl():
    pkgs = parse_osv_alpine_packages(OSV_OPENSSL_SAMPLE)
    assert len(pkgs) == 1
    assert pkgs[0]["vendor"] == "alpine"
    assert pkgs[0]["product"] == "openssl"
    assert pkgs[0]["fixed_version"] == "3.5.7-r0"


def test_parse_osv_alpine_empty():
    assert parse_osv_alpine_packages({}) == []
    assert parse_osv_alpine_packages({"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}}]}) == []


def test_parse_osv_alpine_versioned_ecosystem():
    data = {
        "affected": [
            {
                "package": {"ecosystem": "Alpine:v3.22", "name": "openssl"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.5.7-r0"}],
                    }
                ],
            }
        ]
    }
    pkgs = parse_osv_alpine_packages(data)
    assert len(pkgs) == 1
    assert pkgs[0]["product"] == "openssl"
    assert pkgs[0]["fixed_version"] == "3.5.7-r0"


def test_fetch_cve_packages_invalid_id():
    client = AlpineClient()
    try:
        assert client.fetch_cve_packages("") == []
        assert client.fetch_cve_packages("not-a-cve") == []
    finally:
        client.close()
