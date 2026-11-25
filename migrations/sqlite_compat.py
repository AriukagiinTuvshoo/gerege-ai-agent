"""SQLite batch-migration data transfer that does not destroy timestamps.

=============================================================================
THE BUG THIS WORKS AROUND
=============================================================================
Alembic's batch mode rebuilds a SQLite table by creating a new table, copying rows
with `INSERT INTO new SELECT ... FROM old`, then swapping. When a column's type
changes, `SQLiteImpl.cast_for_batch_migrate()` wraps the old expression in
`CAST(col AS <new_type>)`.

SQLite resolves `CAST(x AS DATETIME)` using **NUMERIC affinity**, because "DATETIME"
contains none of the substrings TEXT/BLOB/REAL/FLOA/INT. Numeric affinity on a
SQLite timestamp string silently produces its leading integer:

    CAST('2026-11-16 04:05:06' AS DATETIME)  ->  2026
    CAST('' AS DATETIME)                     ->  0

Measured with alembic 1.20.1 / SQLAlchemy 2.1.8 / SQLite 3:

    BEFORE  id=1 '2026-11-16 04:05:06' (text)     id=2 ''   (text)
    AFTER   id=1  2026                  (integer)  id=2  0   (integer)

No error is raised and the row counts are unchanged, so this corruption is invisible
to every check that does not inspect `typeof(col)` or the values themselves. It would
have destroyed every timestamp in every SQLite deployment on upgrade.

=============================================================================
THE REPLACEMENT
=============================================================================
For DateTime targets the transfer expression becomes SQLite's own `datetime(col)`:

    datetime('2026-11-16 04:05:06')        -> '2026-11-16 04:05:06'
    datetime('2026-11-16T04:05:06.123456') -> '2026-11-16 04:05:06'
    datetime('')                           -> NULL
    datetime(NULL)                         -> NULL

which normalises the format, maps the legacy empty-string sentinel to NULL (matching
the PostgreSQL `USING NULLIF(btrim(col), '')::timestamp` clause), and keeps the value
as TEXT so SQLAlchemy's DateTime result processor can parse it.

Everything other than DateTime keeps Alembic's default behaviour, including its
special case for JSON.
"""
from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy.dialects import sqlite as sqlite_dialect


def install_sqlite_datetime_transfer_patch() -> None:
    """Patch `SQLiteImpl.cast_for_batch_migrate` to use `datetime()` for DateTime.

    Idempotent: re-installing is a no-op, so it is safe to call from every entry
    point that may run the SQLite path.
    """
    from alembic.ddl.sqlite import SQLiteImpl

    if getattr(SQLiteImpl, "_gerege_datetime_patch", False):
        return

    original = SQLiteImpl.cast_for_batch_migrate

    def cast_for_batch_migrate(
        self: Any,
        existing: Any,
        existing_transfer: dict[str, Any],
        new_type: Any,
    ) -> None:
        if isinstance(new_type, sa.DateTime) and not isinstance(
            new_type, sa.String
        ):
            # SQLite has no real datetime type; `datetime()` normalises TEXT safely
            # whereas `CAST(... AS DATETIME)` applies NUMERIC affinity and truncates.
            existing_transfer["expr"] = func.datetime(existing_transfer["expr"])
            return
        if (
            isinstance(new_type, sqlite_dialect.JSON)
            and existing.type._type_affinity is not new_type._type_affinity
        ):
            # Preserve Alembic's intentional no-cast behaviour for JSON.
            return
        original(self, existing, existing_transfer, new_type)

    SQLiteImpl.cast_for_batch_migrate = cast_for_batch_migrate
    SQLiteImpl._gerege_datetime_patch = True  # type: ignore[attr-defined]
