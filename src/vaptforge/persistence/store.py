from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from vaptforge.models.assessment import (
    AssessmentRecord,
    StatusHistoryRecord,
    StoredFinding,
    ValidationNoteRecord,
)
from vaptforge.models.finding import Evidence, Finding, FindingStatus

ALLOWED_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.DISCOVERED: {
        FindingStatus.POTENTIAL,
        FindingStatus.VERIFIED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.POTENTIAL: {
        FindingStatus.VERIFIED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.VERIFIED: {
        FindingStatus.REMEDIATED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.REMEDIATED: {
        FindingStatus.RETESTED,
        FindingStatus.VERIFIED,
    },
    FindingStatus.RETESTED: {
        FindingStatus.VERIFIED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.FALSE_POSITIVE: {
        FindingStatus.POTENTIAL,
        FindingStatus.VERIFIED,
    },
}


class InvalidStatusTransition(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


class AssessmentStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AssessmentStore:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
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
            """
        )
        self.connection.commit()

    def create_assessment(
        self,
        *,
        name: str,
        authorization_reference: str,
        target: str,
    ) -> AssessmentRecord:
        assessment_id = str(uuid.uuid4())
        now = _now()
        self.connection.execute(
            """
            INSERT INTO assessments
                (id, name, authorization_reference, target, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                name,
                authorization_reference,
                target,
                now.isoformat(),
                now.isoformat(),
            ),
        )
        self.connection.commit()
        return AssessmentRecord(
            id=assessment_id,
            name=name,
            authorization_reference=authorization_reference,
            target=target,
            created_at=now,
            updated_at=now,
        )

    def get_assessment(self, assessment_id: str) -> AssessmentRecord | None:
        row = self.connection.execute(
            "SELECT * FROM assessments WHERE id = ?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            return None
        return AssessmentRecord.model_validate(dict(row))

    def _asset_id(self, assessment_id: str, finding: Finding) -> str:
        asset = finding.asset
        row = self.connection.execute(
            """
            SELECT id FROM assets
            WHERE assessment_id = ?
              AND target = ?
              AND host IS ?
              AND port IS ?
              AND protocol IS ?
              AND service IS ?
            """,
            (
                assessment_id,
                asset.target,
                asset.host,
                asset.port,
                asset.protocol,
                asset.service,
            ),
        ).fetchone()
        if row:
            return str(row["id"])

        asset_id = str(uuid.uuid4())
        self.connection.execute(
            """
            INSERT INTO assets
                (id, assessment_id, target, host, port, protocol, service)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset_id,
                assessment_id,
                asset.target,
                asset.host,
                asset.port,
                asset.protocol,
                asset.service,
            ),
        )
        return asset_id

    def save_finding(self, assessment_id: str, finding: Finding) -> str:
        asset_id = self._asset_id(assessment_id, finding)
        existing = self.connection.execute(
            """
            SELECT id FROM findings
            WHERE assessment_id = ? AND fingerprint = ?
            """,
            (assessment_id, finding.fingerprint),
        ).fetchone()

        now = _now()
        payload = finding.model_dump_json()
        if existing:
            finding_id = str(existing["id"])
            self.connection.execute(
                """
                UPDATE findings
                SET asset_id = ?, payload_json = ?, status = ?, severity = ?,
                    cvss_vector = ?, cvss_score = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    asset_id,
                    payload,
                    finding.status.value,
                    int(finding.severity),
                    finding.cvss_vector,
                    finding.cvss_score,
                    now.isoformat(),
                    finding_id,
                ),
            )
            self.connection.execute("DELETE FROM evidence WHERE finding_id = ?", (finding_id,))
        else:
            finding_id = str(uuid.uuid4())
            self.connection.execute(
                """
                INSERT INTO findings
                    (id, assessment_id, asset_id, fingerprint, payload_json, status,
                     severity, cvss_vector, cvss_score, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    assessment_id,
                    asset_id,
                    finding.fingerprint,
                    payload,
                    finding.status.value,
                    int(finding.severity),
                    finding.cvss_vector,
                    finding.cvss_score,
                    now.isoformat(),
                    now.isoformat(),
                ),
            )

        for evidence in finding.evidence:
            self._insert_evidence(finding_id, evidence)

        self.connection.execute(
            "UPDATE assessments SET updated_at = ? WHERE id = ?",
            (now.isoformat(), assessment_id),
        )
        self.connection.commit()
        return finding_id

    def save_findings(self, assessment_id: str, findings: list[Finding]) -> list[str]:
        return [self.save_finding(assessment_id, finding) for finding in findings]

    def list_findings(self, assessment_id: str) -> list[StoredFinding]:
        rows = self.connection.execute(
            """
            SELECT id, assessment_id, payload_json, created_at, updated_at
            FROM findings
            WHERE assessment_id = ?
            ORDER BY severity DESC, created_at ASC
            """,
            (assessment_id,),
        ).fetchall()
        return [
            StoredFinding(
                id=str(row["id"]),
                assessment_id=str(row["assessment_id"]),
                finding=Finding.model_validate_json(str(row["payload_json"])),
                created_at=datetime.fromisoformat(str(row["created_at"])),
                updated_at=datetime.fromisoformat(str(row["updated_at"])),
            )
            for row in rows
        ]

    def get_finding(self, finding_id: str) -> StoredFinding | None:
        row = self.connection.execute(
            """
            SELECT id, assessment_id, payload_json, created_at, updated_at
            FROM findings WHERE id = ?
            """,
            (finding_id,),
        ).fetchone()
        if row is None:
            return None
        return StoredFinding(
            id=str(row["id"]),
            assessment_id=str(row["assessment_id"]),
            finding=Finding.model_validate_json(str(row["payload_json"])),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
        )

    def transition_finding(
        self,
        finding_id: str,
        new_status: FindingStatus,
        *,
        note: str | None = None,
    ) -> None:
        stored = self.get_finding(finding_id)
        if stored is None:
            raise KeyError(f"Finding not found: {finding_id}")

        old_status = stored.finding.status
        if new_status == old_status:
            return
        if new_status not in ALLOWED_TRANSITIONS[old_status]:
            raise InvalidStatusTransition(
                f"Cannot transition finding from {old_status.value} to {new_status.value}"
            )

        now = _now()
        finding = stored.finding.model_copy(deep=True)
        finding.status = new_status
        self.connection.execute(
            """
            UPDATE findings
            SET status = ?, payload_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status.value, finding.model_dump_json(), now.isoformat(), finding_id),
        )
        self.connection.execute(
            """
            INSERT INTO status_history
                (finding_id, old_status, new_status, note, changed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                old_status.value,
                new_status.value,
                note,
                now.isoformat(),
            ),
        )
        if note:
            self.add_validation_note(finding_id, note, commit=False)
        self.connection.commit()

    def add_validation_note(
        self,
        finding_id: str,
        note: str,
        *,
        commit: bool = True,
    ) -> None:
        if self.get_finding(finding_id) is None:
            raise KeyError(f"Finding not found: {finding_id}")
        self.connection.execute(
            """
            INSERT INTO validation_notes (finding_id, note, created_at)
            VALUES (?, ?, ?)
            """,
            (finding_id, note, _now().isoformat()),
        )
        if commit:
            self.connection.commit()

    def list_validation_notes(self, finding_id: str) -> list[ValidationNoteRecord]:
        rows = self.connection.execute(
            """
            SELECT note, created_at
            FROM validation_notes
            WHERE finding_id = ?
            ORDER BY id ASC
            """,
            (finding_id,),
        ).fetchall()
        return [
            ValidationNoteRecord(
                note=str(row["note"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
            )
            for row in rows
        ]

    def _insert_evidence(self, finding_id: str, evidence: Evidence) -> None:
        self.connection.execute(
            """
            INSERT INTO evidence
                (finding_id, source, summary, raw, attachment_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                evidence.source,
                evidence.summary,
                evidence.raw,
                evidence.attachment_path,
                _now().isoformat(),
            ),
        )

    def add_evidence(self, finding_id: str, evidence: Evidence) -> None:
        stored = self.get_finding(finding_id)
        if stored is None:
            raise KeyError(f"Finding not found: {finding_id}")

        finding = stored.finding.model_copy(deep=True)
        finding.evidence.append(evidence)
        now = _now()
        self._insert_evidence(finding_id, evidence)
        self.connection.execute(
            """
            UPDATE findings SET payload_json = ?, updated_at = ? WHERE id = ?
            """,
            (finding.model_dump_json(), now.isoformat(), finding_id),
        )
        self.connection.commit()

    def status_history(self, finding_id: str) -> list[StatusHistoryRecord]:
        rows = self.connection.execute(
            """
            SELECT old_status, new_status, note, changed_at
            FROM status_history
            WHERE finding_id = ?
            ORDER BY id ASC
            """,
            (finding_id,),
        ).fetchall()
        return [
            StatusHistoryRecord(
                old_status=FindingStatus(str(row["old_status"])),
                new_status=FindingStatus(str(row["new_status"])),
                note=str(row["note"]) if row["note"] is not None else None,
                changed_at=datetime.fromisoformat(str(row["changed_at"])),
            )
            for row in rows
        ]
