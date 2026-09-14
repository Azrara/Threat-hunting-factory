"""Database engine and session helpers."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

settings.ensure_dirs()

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create every table declared on the metadata, and add columns it is missing."""
    from . import models  # noqa: F401  (import registers the models)

    Base.metadata.create_all(bind=engine)
    add_missing_columns()


def add_missing_columns() -> None:
    """Add columns that exist on a model but not yet in the database.

    ``create_all`` creates tables and never alters them, so a database written by
    an earlier version keeps its old shape and every query against a new column
    fails. This closes that gap for the one case that actually occurs here:
    a column added to an existing table, with a default and no constraint.

    It is deliberately narrow. Anything beyond adding a nullable or defaulted
    column (renames, type changes, indexes) is not attempted and would need a real
    migration.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    # Column names such as "references" are reserved words, so every identifier is
    # quoted the way the dialect would quote it rather than interpolated raw.
    quote = engine.dialect.identifier_preparer.quote
    with engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            present = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present or column.primary_key:
                    continue
                if not (column.nullable or column.default is not None):
                    continue
                kind = column.type.compile(dialect=engine.dialect)
                default = _default_clause(column)
                connection.execute(
                    text(
                        f"ALTER TABLE {quote(table.name)} "
                        f"ADD COLUMN {quote(column.name)} {kind}{default}"
                    )
                )


def _default_clause(column) -> str:
    default = getattr(column.default, "arg", None)
    if default is None or callable(default):
        return ""
    if isinstance(default, bool):
        return f" DEFAULT {1 if default else 0}"
    if isinstance(default, (int, float)):
        return f" DEFAULT {default}"
    if isinstance(default, str):
        escaped = default.replace("'", "''")
        return f" DEFAULT '{escaped}'"
    return ""
