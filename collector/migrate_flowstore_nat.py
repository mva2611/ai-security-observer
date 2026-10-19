#!/usr/bin/env python3
"""Fail-closed SQLite migration adding NAT and flow-time provenance columns."""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from pathlib import Path

NAT_COLUMNS = {
    "post_nat_src_ip": "TEXT",
    "post_nat_dst_ip": "TEXT",
    "post_napt_src_port": "INTEGER",
    "post_napt_dst_port": "INTEGER",
}

TIME_COLUMNS = {
    "flow_time_source": (
        "TEXT NOT NULL DEFAULT 'export_fallback' "
        "CHECK (flow_time_source IN "
        "('absolute', 'reconstructed', 'export_fallback'))"
    ),
}

MIGRATION_COLUMNS = {**NAT_COLUMNS, **TIME_COLUMNS}


def integrity_check(db: sqlite3.Connection) -> None:
    result = db.execute("PRAGMA integrity_check").fetchone()
    if result != ("ok",):
        raise RuntimeError(f"integrity_check failed: {result!r}")


def table_columns(db: sqlite3.Connection) -> set[str]:
    if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='flows'"
    ).fetchone() is None:
        raise RuntimeError("table 'flows' not found")
    return {row[1] for row in db.execute("PRAGMA table_info(flows)")}


def migrate(database: Path, backup: Path) -> str:
    try:
        database = database.expanduser().resolve(strict=True)
        backup_parent = backup.expanduser().parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"path not found: {exc.filename}") from exc
    backup = backup_parent / backup.name

    if not database.is_file():
        raise RuntimeError(f"database is not a regular file: {database}")
    if database == backup:
        raise RuntimeError("database and backup resolve to the same path")
    if backup.is_symlink():
        raise RuntimeError(f"backup path must not be a symlink: {backup}")
    if backup.exists():
        raise RuntimeError(f"backup already exists: {backup}")

    with sqlite3.connect(database) as db:
        integrity_check(db)
        existing = table_columns(db)
        present = set(NAT_COLUMNS) & existing
        if present and present != set(NAT_COLUMNS):
            raise RuntimeError(
                "partial NAT migration detected: " + ", ".join(sorted(present))
            )
        if present == set(NAT_COLUMNS) and set(TIME_COLUMNS) <= existing:
            return "already migrated; no backup or changes made"

        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        page_count = db.execute("PRAGMA page_count").fetchone()[0]
        logical_size = page_size * page_count
        safety_margin = max(256 * 1024 * 1024, (logical_size + 9) // 10)
        required_free = logical_size + safety_margin
        available_free = shutil.disk_usage(backup_parent).free
        if available_free < required_free:
            raise RuntimeError(
                "insufficient backup space: "
                f"required={required_free} available={available_free}"
            )

        with sqlite3.connect(backup) as backup_db:
            db.backup(backup_db)
            integrity_check(backup_db)

        try:
            db.execute("BEGIN IMMEDIATE")
            for name, column_type in MIGRATION_COLUMNS.items():
                if name not in existing:
                    db.execute(f"ALTER TABLE flows ADD COLUMN {name} {column_type}")
            db.commit()
        except Exception:
            db.rollback()
            raise

        integrity_check(db)
        missing = set(MIGRATION_COLUMNS) - table_columns(db)
        if missing:
            raise RuntimeError("migration verification failed: " + ", ".join(sorted(missing)))
        invalid_sources = db.execute(
            "SELECT count(*) FROM flows WHERE flow_time_source IS NULL "
            "OR flow_time_source NOT IN "
            "('absolute', 'reconstructed', 'export_fallback')"
        ).fetchone()[0]
        if invalid_sources:
            raise RuntimeError(
                f"migration verification failed: {invalid_sources} invalid flow_time_source rows"
            )

    return f"migration complete; backup={backup}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    parser.add_argument("backup", type=Path)
    args = parser.parse_args()
    try:
        print(migrate(args.database, args.backup))
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
