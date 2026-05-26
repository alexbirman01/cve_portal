"""Unit tests for Go/stdlib Aqua package routing."""

from __future__ import annotations

import pytest

from api.app.aqua_packages import (
    GO_AQUA_RESOURCE,
    is_nvd_go_packages,
    match_package_in_catalog,
    resolve_aqua_search_name,
)


# ─── is_nvd_go_packages ───────────────────────────────────────────────────────

def test_is_nvd_go_packages_true():
    pkgs = [{"vendor": "golang", "product": "go"}]
    assert is_nvd_go_packages(pkgs) is True


def test_is_nvd_go_packages_case_insensitive():
    pkgs = [{"vendor": "Golang", "product": "go"}]
    assert is_nvd_go_packages(pkgs) is True


def test_is_nvd_go_packages_false():
    pkgs = [{"vendor": "oracle", "product": "jre"}]
    assert is_nvd_go_packages(pkgs) is False


def test_is_nvd_go_packages_empty():
    assert is_nvd_go_packages([]) is False


def test_is_nvd_go_packages_mixed_list():
    pkgs = [{"vendor": "oracle", "product": "jre"}, {"vendor": "golang", "product": "go"}]
    assert is_nvd_go_packages(pkgs) is True


# ─── resolve_aqua_search_name ────────────────────────────────────────────────

def test_resolve_golang_returns_stdlib():
    pkgs = [{"vendor": "golang", "product": "go"}]
    assert resolve_aqua_search_name(pkgs, "go") == GO_AQUA_RESOURCE


def test_resolve_non_go_returns_fallback():
    pkgs = [{"vendor": "oracle", "product": "jre"}]
    assert resolve_aqua_search_name(pkgs, "jre") == "jre"


def test_resolve_empty_packages_returns_fallback():
    assert resolve_aqua_search_name([], "netty") == "netty"


def test_resolve_fallback_stripped():
    assert resolve_aqua_search_name([], "  netty  ") == "netty"


# ─── match_package_in_catalog candidates for Go ──────────────────────────────

def test_go_miss_injects_stdlib_candidate_first():
    """When catalog has no stdlib and is_go=True, stdlib appears first in candidates."""
    catalog = [{"name": "unrelated-lib", "version": "1.0"}]
    result = match_package_in_catalog(
        catalog,
        "stdlib",
        customer_name="net",
        nvd_name="go",
        is_go=True,
    )
    assert result.found is False
    names = [c.name for c in result.candidates]
    assert names[0] == GO_AQUA_RESOURCE
    assert "go" in names or "net" in names


def test_go_miss_no_aqua_hint_from_unrelated_catalog():
    """Aqua substring hint is suppressed for Go rows — no misleading module names."""
    catalog = [{"name": "golang-crypto", "version": "0.1"}]
    result = match_package_in_catalog(
        catalog,
        "stdlib",
        is_go=True,
    )
    # candidates should have stdlib (aqua), not golang-crypto
    names = [c.name for c in result.candidates]
    assert GO_AQUA_RESOURCE in names
    assert "golang-crypto" not in names


def test_go_hit_when_stdlib_in_catalog():
    """When Aqua catalog contains 'stdlib', the match is found."""
    catalog = [{"name": "stdlib", "version": "1.21.0"}]
    result = match_package_in_catalog(catalog, "stdlib", is_go=True)
    assert result.found is True
    assert result.aqua_package_name == "stdlib"


def test_non_go_miss_uses_aqua_hint():
    """Non-Go miss still falls back to aqua hint from catalog."""
    catalog = [{"name": "netty-codec-http", "version": "4.1.0"}]
    result = match_package_in_catalog(
        catalog,
        "netty",
        customer_name="netty",
        nvd_name="netty",
        is_go=False,
    )
    assert result.found is False
    names = [c.name for c in result.candidates]
    assert "netty-codec-http" in names
