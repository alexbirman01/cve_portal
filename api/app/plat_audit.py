"""Structured stdout audit lines for PLAT lookup and create (grep: plat_lookup_audit / plat_create_audit)."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

logger = logging.getLogger("cve_portal.plat_audit")


def log_plat_audit(event: str, **fields: object) -> None:
    """Emit one JSON audit line to pod stdout."""
    payload: dict[str, object] = {
        "event": event,
        "ts": datetime.now(UTC).isoformat(),
        **fields,
    }
    logger.info(json.dumps(payload, default=str))
