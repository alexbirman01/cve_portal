"""Known JSM *Organization* display names (not Jira API enums — the REST API still uses numeric/org ids)."""

from __future__ import annotations

from enum import StrEnum

from api.app.config import settings


class PlatOrganizationLabel(StrEnum):
    """
    Labels as they appear on the Jira Organization field; must match the JSM org directory spelling.
    Add members here when you onboard customers; resolves to ids via servicedesk `GET .../organization`.
    """

    ACCENTURE = "Accenture"
    BANK_LEUMI = "BankLeumi"
    CISCO = "Cisco"
    CITI = "Citi"
    COUPANG = "Coupang"
    DTCC = "DTCC"
    FANNIE_MAE = "FannieMae"
    GLOBAL = "Global"
    HUMANA = "Humana"
    NOVARTIS = "Novartis"
    ROCHE = "Roche"
    WELLS_FARGO = "WellsFargo"


def plat_organization_name_allowed(name: str, *, restrict_to_enum: bool) -> bool:
    if not restrict_to_enum:
        return True
    n = name.strip().casefold()
    if not n:
        return True
    raw = (settings.jira_plat_organization_name_allowlist or "").strip()
    if raw:
        allowed = {p.strip().casefold() for p in raw.split(",") if p.strip()}
        return n in allowed
    return any(n == m.casefold() for m in PlatOrganizationLabel)
