"""Parse customer SLA matrix cells and compute strictest due date (calendar date) from anchor + orgs + severity."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParsedSlaCell:
    usable: bool
    best_efforts: bool
    days: int
    business_days: bool


def _strip_noise(text: str) -> str:
    s = text.strip()
    s = re.sub(r"\s*\([^)]*\)\s*$", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def parse_sla_cell(text: str | None) -> ParsedSlaCell | None:
    if text is None:
        return None
    raw = str(text).strip()
    if not raw:
        return None
    low = _strip_noise(raw).lower()
    if low in ("n/a", "na"):
        return ParsedSlaCell(usable=False, best_efforts=False, days=0, business_days=False)
    if "best effort" in low:
        return ParsedSlaCell(usable=True, best_efforts=True, days=0, business_days=False)
    if "immediately" in low:
        return ParsedSlaCell(usable=True, best_efforts=False, days=0, business_days=False)

    business = "business" in low
    m = re.search(r"(\d+)", low)
    if not m:
        return ParsedSlaCell(usable=True, best_efforts=True, days=0, business_days=False)
    n = int(m.group(1))
    return ParsedSlaCell(usable=True, best_efforts=False, days=n, business_days=business)


def severity_column(upper: str | None) -> str | None:
    if not upper:
        return None
    u = upper.strip().upper()
    if u == "CRITICAL":
        return "critical"
    if u == "HIGH":
        return "high"
    if u == "MEDIUM":
        return "medium"
    if u == "LOW":
        return "low"
    return None


def sla_cell_for_column(row: dict[str, Any], col: str | None) -> str | None:
    if col is None:
        return None
    key = f"sla_{col}"
    v = row.get(key)
    if v is None:
        return None
    return str(v)


def effective_days_for_min(parsed: ParsedSlaCell) -> int | None:
    if not parsed.usable or parsed.best_efforts:
        return None
    return parsed.days


def add_calendar_days(anchor: dt.datetime, n: int) -> dt.date:
    if n <= 0:
        return anchor.astimezone(dt.UTC).date()
    d = anchor.astimezone(dt.UTC).date()
    return d + dt.timedelta(days=n)


def add_business_days(anchor: dt.datetime, n: int) -> dt.date:
    if n <= 0:
        return anchor.astimezone(dt.UTC).date()
    remaining = n
    cur = anchor.astimezone(dt.UTC).date()
    while remaining > 0:
        cur = cur + dt.timedelta(days=1)
        if cur.weekday() < 5:
            remaining -= 1
    return cur


def due_date_from_anchor(
    anchor: dt.datetime | None,
    org_names: list[str],
    severity: str | None,
    rows_by_customer_lower: dict[str, dict[str, Any]],
) -> str | None:
    if anchor is None:
        return None
    col = severity_column(severity)
    if col is None:
        return None

    dates: list[dt.date] = []
    for name in org_names:
        if not name or not str(name).strip():
            continue
        row = rows_by_customer_lower.get(name.strip().casefold())
        if not row:
            continue
        parsed = parse_sla_cell(sla_cell_for_column(row, col))
        if parsed is None:
            continue
        if effective_days_for_min(parsed) is None:
            continue
        if parsed.business_days:
            dates.append(add_business_days(anchor, parsed.days))
        else:
            dates.append(add_calendar_days(anchor, parsed.days))

    if not dates:
        return None
    return min(dates).isoformat()


def parse_jira_created(raw: str | None) -> dt.datetime | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    elif re.match(r".*[+-]\d{4}$", s) and ":" not in s[-6:]:
        s = s[:-5] + s[-5:-2] + ":" + s[-2:]
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.UTC)
    return d.astimezone(dt.UTC)
