from __future__ import annotations

import sqlite3
from dataclasses import dataclass


class DatabaseVersionError(RuntimeError):
    """Raised when a database schema is newer than this VAPTForge build."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str


MIGRATIONS = (
    Migration(
        version=1,
        name="initial-assessment-schema",
        sql="""
        CREATE TABLE IF NOT EXISTS assessments (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            authorization_reference TEXT NOT NULL,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            target TEXT NOT NULL,
            host TEXT,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            UNIQUE(assessment_id, target, host, port, protocol, service)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
            fingerprint TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL,
            severity INTEGER NOT NULL,
            cvss_vector TEXT,
            cvss_score REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(assessment_id, fingerprint)
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            summary TEXT NOT NULL,
            raw TEXT,
            attachment_path TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            old_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            note TEXT,
            changed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS validation_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS retest_runs (
            id TEXT PRIMARY KEY,
            before_assessment_id TEXT NOT NULL
                REFERENCES assessments(id) ON DELETE CASCADE,
            after_assessment_id TEXT NOT NULL
                REFERENCES assessments(id) ON DELETE CASCADE,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """,
    ),
    Migration(
        version=2,
        name="scanner-run-audit",
        sql="""
        CREATE TABLE IF NOT EXISTS scanner_runs (
            id TEXT PRIMARY KEY,
            assessment_id TEXT REFERENCES assessments(id) ON DELETE CASCADE,
            scanner TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            finding_count INTEGER NOT NULL DEFAULT 0,
            error_message TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_findings_assessment_severity
            ON findings(assessment_id, severity);
        CREATE INDEX IF NOT EXISTS idx_evidence_finding
            ON evidence(finding_id);
        CREATE INDEX IF NOT EXISTS idx_scanner_runs_assessment
            ON scanner_runs(assessment_id, started_at);
        """,
    ),
)

SCHEMA_VERSION = MIGRATIONS[-1].version


def current_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row is not None else 0


def apply_migrations(connection: sqlite3.Connection) -> int:
    current = current_schema_version(connection)
    if current > SCHEMA_VERSION:
        raise DatabaseVersionError(
            f"Database schema version {current} is newer than supported version "
            f"{SCHEMA_VERSION}. Upgrade VAPTForge before opening this database."
        )

    for migration in MIGRATIONS:
        if migration.version <= current:
            continue
        try:
            connection.executescript(migration.sql)
            connection.execute(f"PRAGMA user_version = {migration.version}")
            connection.commit()
        except sqlite3.DatabaseError:
            connection.rollback()
            raise
        current = migration.version

    return current
