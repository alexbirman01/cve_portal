"""Upsert the canonical PlainID image catalog into allowed_images.

Run: docker compose exec api python -m api.app.seed_allowed_images
"""

from __future__ import annotations

from api.app.db import SessionLocal
from api.app.models import AllowedImage

_CATALOG: list[str] = [
    "os-shell",
    "redis-exporter",
    "redis-sentinel",
    "busybox",
    "redis",
    "haproxy",
    "shellcheck",
    "redis_exporter",
    "agent",
    "idp-webhook",
    "pip-operator",
    "secrets-mgmt",
    "theruntime",
    "authz-sql-pdp-modifier",
    "rclone",
    "authz-access-file",
    "authz-jsonmasking",
    "authz-envoy-sidecar",
]


def main() -> None:
    session = SessionLocal()
    n_new = 0
    n_updated = 0
    try:
        for raw_name in _CATALOG:
            name = raw_name.strip().lower()
            if not name:
                continue
            row = session.query(AllowedImage).filter(AllowedImage.name == name).one_or_none()
            if row is None:
                session.add(AllowedImage(name=name))
                n_new += 1
            else:
                n_updated += 1
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    print(f"allowed_images: {n_new} inserted, {n_updated} already present (total {len(_CATALOG)} in catalog).")


if __name__ == "__main__":
    main()
