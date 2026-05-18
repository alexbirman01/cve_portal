from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import settings


engine = create_engine(
    settings.postgres_dsn,
    pool_pre_ping=True,
    connect_args={"options": "-c search_path=public"},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def db_session() -> Session:
    return SessionLocal()

