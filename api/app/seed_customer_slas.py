"""Upsert customer_slas from PM SLA matrix.

Run: docker compose exec api python -m api.app.seed_customer_slas
"""

from __future__ import annotations

from api.app.db import SessionLocal
from api.app.models import CustomerSla

_SLA_ROWS: list[tuple[str, str, str, str, str]] = [
    ("Accenture PBAC", "21 business days", "30 business days", "60 business days", "Best Efforts"),
    ("Bank Leumi", "14 days", "14 days", "30 days", "180 days"),
    ("Centric", "N/A", "N/A", "N/A", "N/A"),
    ("Cisco", "21 days", "N/A", "N/A", "N/A"),
    ("Citi", "N/A", "N/A", "N/A", "N/A"),
    ("Desjardins", "30 days", "60 days", "90 days", "180 days"),
    ("EYG", "N/A", "N/A", "N/A", "N/A"),
    ("FMG", "Immediately", "30 days", "60 days", "90 days"),
    ("Humana", "30 days", "30 days", "90 days", "90 days"),
    ("Northern Trust", "N/A", "N/A", "N/A", "N/A"),
    ("Telenet", "N/A", "N/A", "N/A", "N/A"),
    ("Vonage", "N/A", "N/A", "N/A", "N/A"),
    ("Thales", "N/A", "N/A", "N/A", "N/A"),
    ("Roche", "N/A", "N/A", "N/A", "N/A"),
]


def main() -> None:
    session = SessionLocal()
    n_new = 0
    n_updated = 0
    try:
        for name, crit, high, med, low in _SLA_ROWS:
            row = session.query(CustomerSla).filter(CustomerSla.customer_name == name).one_or_none()
            if row is None:
                session.add(
                    CustomerSla(
                        customer_name=name,
                        sla_critical=crit,
                        sla_high=high,
                        sla_medium=med,
                        sla_low=low,
                    )
                )
                n_new += 1
            else:
                row.sla_critical = crit
                row.sla_high = high
                row.sla_medium = med
                row.sla_low = low
                session.add(row)
                n_updated += 1
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    print(f"customer_slas: {n_new} inserted, {n_updated} updated (total {len(_SLA_ROWS)} in matrix).")


if __name__ == "__main__":
    main()
