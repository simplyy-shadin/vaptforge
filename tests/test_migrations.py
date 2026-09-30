import sqlite3

import pytest

from vaptforge.persistence.migrations import DatabaseVersionError, SCHEMA_VERSION
from vaptforge.persistence.store import AssessmentStore


def test_new_database_is_migrated_to_latest_schema(tmp_path) -> None:
    database = tmp_path / "vaptforge.db"

    with AssessmentStore(database) as store:
        assert store.schema_version == SCHEMA_VERSION
        tables = {
            row["name"]
            for row in store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert "assessments" in tables
    assert "scanner_runs" in tables


def test_unversioned_legacy_database_is_upgraded_in_place(tmp_path) -> None:
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE assessments (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            authorization_reference TEXT NOT NULL,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()

    with AssessmentStore(database) as store:
        assert store.schema_version == SCHEMA_VERSION
        scanner_runs = store.connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scanner_runs'"
        ).fetchone()

    assert scanner_runs is not None


def test_newer_database_version_is_rejected(tmp_path) -> None:
    database = tmp_path / "future.db"
    connection = sqlite3.connect(database)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 10}")
    connection.close()

    with pytest.raises(DatabaseVersionError):
        AssessmentStore(database)
