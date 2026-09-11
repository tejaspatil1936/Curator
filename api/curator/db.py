"""SQLAlchemy engine and session factory.

One pooled engine per process. Creating it does not connect, so the API starts even
while the database is still booting; connections are opened lazily on first use.
"""

import logging
from collections.abc import Iterator

from sqlalchemy import URL, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from curator.config import settings

logger = logging.getLogger(__name__)

DATABASE_URL = URL.create(
    drivername="postgresql+psycopg",
    username=settings.postgres_user,
    password=settings.postgres_password.get_secret_value(),
    host=settings.postgres_host,
    port=settings.postgres_port,
    database=settings.postgres_db,
)

engine = create_engine(
    DATABASE_URL,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,  # drop connections killed by a DB restart before reuse
    pool_recycle=1800,
    pool_timeout=5,
    connect_args={"connect_timeout": settings.db_connect_timeout_s},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    with SessionLocal() as session:
        yield session


def ping() -> bool:
    """Round-trip SELECT 1. Returns False instead of raising."""
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar_one() == 1
    except SQLAlchemyError as exc:
        logger.warning("database ping failed: %s", exc.__class__.__name__)
        return False
