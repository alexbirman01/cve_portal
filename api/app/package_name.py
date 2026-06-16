"""Normalize scanner/distro package names for PLAT and findings display."""

from __future__ import annotations

import re

_PKG_NAME_SPLIT_RE = re.compile(r"[,;]+")


def canonical_single_package_name(name: str | None) -> str | None:
    """
    Return a single package name when scanners join multiple values in one field.

    Prisma and similar tools often emit ``libssl3,libcrypto3`` for one upstream fix;
    PLAT tickets need one Package Name — we keep the first non-empty token.
    """
    if name is None:
        return None
    s = str(name).strip()
    if not s:
        return None
    parts = [p.strip() for p in _PKG_NAME_SPLIT_RE.split(s) if p.strip()]
    return parts[0] if parts else None
