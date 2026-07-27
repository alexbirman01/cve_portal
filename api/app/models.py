from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ProcessingRun(Base):
    __tablename__ = "processing_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issue_key: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    celery_task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.UTC),
        onupdate=lambda: dt.datetime.now(dt.UTC),
    )


class CustomerSla(Base):
    __tablename__ = "customer_slas"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_name: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    sla_critical: Mapped[str | None] = mapped_column(Text, nullable=True)
    sla_high: Mapped[str | None] = mapped_column(Text, nullable=True)
    sla_medium: Mapped[str | None] = mapped_column(Text, nullable=True)
    sla_low: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.UTC),
        onupdate=lambda: dt.datetime.now(dt.UTC),
    )


class AllowedImage(Base):
    __tablename__ = "allowed_images"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    aliases: Mapped[str] = mapped_column(String(1024), nullable=False, server_default="", default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.UTC),
        onupdate=lambda: dt.datetime.now(dt.UTC),
    )


class CveCache(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[str] = mapped_column(String(32), default="unknown")  # ok | not_found | error
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    score: Mapped[str | None] = mapped_column(String(16), nullable=True)
    published: Mapped[str | None] = mapped_column(String(32), nullable=True)
    modified: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))


class PortalSetting(Base):
    """Key-value portal configuration (e.g. Aqua cache TTL)."""

    __tablename__ = "portal_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.UTC),
        onupdate=lambda: dt.datetime.now(dt.UTC),
    )


class AquaImagePackages(Base):
    """Cached Aqua resource catalog per scanned image (registry + repository + tag)."""

    __tablename__ = "aqua_image_packages"

    registry: Mapped[str] = mapped_column(String(256), primary_key=True)
    repository: Mapped[str] = mapped_column(String(512), primary_key=True)
    tag: Mapped[str] = mapped_column(String(256), primary_key=True)
    packages_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    fetched_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.UTC),
    )


class IssueSyncSchedule(Base):
    """Per-ticket optional daily Sync PLAT schedule (dashboard checkbox)."""

    __tablename__ = "issue_sync_schedules"

    issue_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    daily_sync_enabled: Mapped[bool] = mapped_column(default=False)
    last_auto_sync_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.UTC),
        onupdate=lambda: dt.datetime.now(dt.UTC),
    )

