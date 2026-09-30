"""Durable local assessment queue and scanner-run audit records."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.persistence.store import AssessmentStore


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScannerRun(BaseModel):
    id: str
    assessment_id: str
    job_id: str | None
    position: int | None
    scanner: str
    target: str
    status: JobStatus
    started_at: datetime | None
    finished_at: datetime | None
    finding_count: int
    error_message: str | None


class AssessmentJob(BaseModel):
    id: str
    assessment_id: str
    target: str
    scope: AuthorizedScope
    status: JobStatus
    cancel_requested: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    scanner_runs: list[ScannerRun]


class WorkerBusyError(RuntimeError):
    """Another local worker holds the lease."""


def _now() -> datetime:
    return datetime.now(UTC)


class JobStore(AssessmentStore):
    def __init__(self, path: str | Path) -> None:
        super().__init__(path)
        self.connection.execute("PRAGMA busy_timeout = 5000")

    def enqueue(self, target: str, scope: AuthorizedScope, scanners: list[str]) -> AssessmentJob:
        scope.require_authorized(target)
        if not scanners or len(scanners) != len(set(scanners)):
            raise ValueError("Select at least one scanner, without duplicates")
        assessment_id, job_id = str(uuid.uuid4()), str(uuid.uuid4())
        now = _now().isoformat()
        with self.connection:
            self.connection.execute(
                """INSERT INTO assessments
                (id, name, authorization_reference, target, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    assessment_id,
                    scope.assessment_name,
                    scope.authorization_reference,
                    target,
                    now,
                    now,
                ),
            )
            self.connection.execute(
                """INSERT INTO assessment_jobs
                (id, assessment_id, target, scope_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (job_id, assessment_id, target, scope.model_dump_json(), JobStatus.QUEUED, now),
            )
            for position, scanner in enumerate(scanners):
                self.connection.execute(
                    """INSERT INTO scanner_runs
                    (id, assessment_id, job_id, position, scanner, target, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        assessment_id,
                        job_id,
                        position,
                        scanner,
                        target,
                        JobStatus.QUEUED,
                    ),
                )
        job = self.get_job(job_id)
        if job is None:
            raise RuntimeError("Queued job disappeared")
        return job

    def get_job(self, job_id: str) -> AssessmentJob | None:
        row = self.connection.execute(
            "SELECT * FROM assessment_jobs WHERE id = ?", (job_id,)
        ).fetchone()
        if row is None:
            return None
        runs = self.connection.execute(
            "SELECT * FROM scanner_runs WHERE job_id = ? ORDER BY position", (job_id,)
        ).fetchall()
        return AssessmentJob(
            id=row["id"],
            assessment_id=row["assessment_id"],
            target=row["target"],
            scope=AuthorizedScope.model_validate_json(row["scope_json"]),
            status=row["status"],
            cancel_requested=bool(row["cancel_requested"]),
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            error_message=row["error_message"],
            scanner_runs=[ScannerRun.model_validate(dict(item)) for item in runs],
        )

    def list_jobs(self, assessment_id: str | None = None) -> list[AssessmentJob]:
        if assessment_id is None:
            rows = self.connection.execute(
                "SELECT id FROM assessment_jobs ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT id FROM assessment_jobs WHERE assessment_id = ? ORDER BY created_at DESC",
                (assessment_id,),
            ).fetchall()
        return [job for row in rows if (job := self.get_job(row["id"])) is not None]

    def cancel(self, job_id: str) -> AssessmentJob:
        with self.connection:
            row = self.connection.execute(
                "SELECT status FROM assessment_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Job not found: {job_id}")
            if row["status"] in (JobStatus.QUEUED, JobStatus.RUNNING):
                self.connection.execute(
                    "UPDATE assessment_jobs SET cancel_requested = 1 WHERE id = ?", (job_id,)
                )
                if row["status"] == JobStatus.QUEUED:
                    self.finish_job(job_id, JobStatus.CANCELLED, commit=False)
        job = self.get_job(job_id)
        if job is None:
            raise RuntimeError("Cancelled job disappeared")
        return job

    def acquire_lease(self, owner: str, ttl: int = 45) -> None:
        now = _now()
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute("SELECT * FROM worker_lease WHERE id = 1").fetchone()
            if row and datetime.fromisoformat(row["expires_at"]) > now:
                raise WorkerBusyError("Another assessment worker is active")
            self.connection.execute(
                "INSERT OR REPLACE INTO worker_lease (id, owner, expires_at) VALUES (1, ?, ?)",
                (owner, (now + timedelta(seconds=ttl)).isoformat()),
            )
            # A dead worker may have left a scanner running. Retry that scanner;
            # completed scanner results remain durable and are not rerun.
            self.connection.execute(
                "UPDATE assessment_jobs SET status = 'queued' WHERE status = 'running'"
            )
            self.connection.execute(
                """UPDATE scanner_runs SET status = 'queued', started_at = NULL,
                error_message = NULL WHERE status = 'running' AND job_id IS NOT NULL"""
            )

    def renew_lease(self, owner: str, ttl: int = 45) -> bool:
        with self.connection:
            updated = self.connection.execute(
                """UPDATE worker_lease SET expires_at = ?
                WHERE id = 1 AND owner = ? AND expires_at > ?""",
                ((_now() + timedelta(seconds=ttl)).isoformat(), owner, _now().isoformat()),
            ).rowcount
        return updated == 1

    def owns_lease(self, owner: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM worker_lease WHERE owner = ? AND expires_at > ?",
                (owner, _now().isoformat()),
            ).fetchone()
            is not None
        )

    def release_lease(self, owner: str) -> None:
        with self.connection:
            self.connection.execute("DELETE FROM worker_lease WHERE owner = ?", (owner,))

    def claim_next(self, owner: str) -> AssessmentJob | None:
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            if not self.owns_lease(owner):
                raise WorkerBusyError("Worker lease lost")
            row = self.connection.execute(
                """SELECT id FROM assessment_jobs WHERE status = 'queued'
                ORDER BY created_at, rowid LIMIT 1"""
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                """UPDATE assessment_jobs SET status = 'running',
                started_at = COALESCE(started_at, ?) WHERE id = ?""",
                (_now().isoformat(), row["id"]),
            )
        return self.get_job(row["id"])

    def start_run(self, run_id: str) -> None:
        with self.connection:
            self.connection.execute(
                """UPDATE scanner_runs SET status = 'running', started_at = ?
                WHERE id = ? AND status = 'queued'""",
                (_now().isoformat(), run_id),
            )

    def finish_run(
        self,
        run_id: str,
        status: JobStatus,
        findings: list[Finding] | None = None,
        error: str | None = None,
    ) -> None:
        with self.connection:
            self.connection.execute(
                """UPDATE scanner_runs SET status = ?, finished_at = ?, finding_count = ?,
                error_message = ?, result_json = ? WHERE id = ? AND status = 'running'""",
                (
                    status,
                    _now().isoformat(),
                    len(findings or []),
                    error,
                    json.dumps([item.model_dump(mode="json") for item in findings])
                    if findings is not None
                    else None,
                    run_id,
                ),
            )

    def results(self, job_id: str) -> list[Finding]:
        rows = self.connection.execute(
            """SELECT result_json FROM scanner_runs WHERE job_id = ?
            AND status = 'succeeded' ORDER BY position""",
            (job_id,),
        ).fetchall()
        return [
            Finding.model_validate(item)
            for row in rows
            if row["result_json"]
            for item in json.loads(row["result_json"])
        ]

    def finish_job(
        self, job_id: str, status: JobStatus, error: str | None = None, *, commit: bool = True
    ) -> None:
        now = _now().isoformat()
        self.connection.execute(
            """UPDATE assessment_jobs SET status = ?, finished_at = ?,
            error_message = ? WHERE id = ?""",
            (status, now, error, job_id),
        )
        if status == JobStatus.CANCELLED:
            self.connection.execute(
                """UPDATE scanner_runs SET status = 'cancelled', finished_at = ?
                WHERE job_id = ? AND status = 'queued'""",
                (now, job_id),
            )
        if commit:
            self.connection.commit()
