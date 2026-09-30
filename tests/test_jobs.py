from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vaptforge.api.main import create_app
from vaptforge.jobs.worker import AssessmentWorker
from vaptforge.models.finding import AssetRef, Finding, FindingStatus
from vaptforge.models.scope import AuthorizedScope, ScopeEntry
from vaptforge.persistence.jobs import JobStatus, JobStore, WorkerBusyError
from vaptforge.scanners.base import Scanner


class FakeScanner(Scanner):
    name = "fake"

    def __init__(self, *, fail: bool = False, cancel: tuple[Path, str] | None = None):
        self.calls = 0
        self.fail = fail
        self.cancel_job = cancel

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        self.calls += 1
        if self.cancel_job:
            database, job_id = self.cancel_job
            with JobStore(database) as store:
                store.cancel(job_id)
        if self.fail:
            raise RuntimeError("scanner unavailable")
        return [Finding(title="A candidate", asset=AssetRef(target=target), source=self.name)]


def scope() -> AuthorizedScope:
    return AuthorizedScope(
        assessment_name="Owned lab",
        authorization_reference="AUTH-1",
        targets=[ScopeEntry(value="127.0.0.1")],
    )


def test_queue_rejects_out_of_scope_and_duplicates(tmp_path: Path) -> None:
    with JobStore(tmp_path / "jobs.db") as store:
        with pytest.raises(PermissionError):
            store.enqueue("http://example.org", scope(), ["fake"])
        with pytest.raises(ValueError):
            store.enqueue("http://127.0.0.1", scope(), ["fake", "fake"])
        assert store.list_assessments() == []


def test_worker_persists_progress_and_findings(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    with JobStore(database) as store:
        job = store.enqueue("http://127.0.0.1:3000", scope(), ["fake"])
    fake = FakeScanner()
    assert AssessmentWorker(database, scanners={"fake": fake}).run_once() == job.id
    with JobStore(database) as store:
        result = store.get_job(job.id)
        assert result.status == JobStatus.SUCCEEDED
        assert result.scanner_runs[0].finding_count == 1
        assert result.scanner_runs[0].started_at and result.finished_at
        findings = store.list_findings(job.assessment_id)
        assert len(findings) == 1
        assert findings[0].finding.status == FindingStatus.DISCOVERED
    assert fake.calls == 1


def test_scanner_failure_is_isolated_and_following_scanner_runs(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    with JobStore(database) as store:
        job = store.enqueue("127.0.0.1", scope(), ["broken", "good"])
    AssessmentWorker(
        database, scanners={"broken": FakeScanner(fail=True), "good": FakeScanner()}
    ).run_once()
    with JobStore(database) as store:
        result = store.get_job(job.id)
        assert result.status == JobStatus.FAILED
        assert [run.status for run in result.scanner_runs] == [
            JobStatus.FAILED,
            JobStatus.SUCCEEDED,
        ]
        assert len(store.list_findings(job.assessment_id)) == 1
        assert "scanner unavailable" in result.error_message


def test_cancel_queued_and_between_scanners(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    with JobStore(database) as store:
        queued = store.enqueue("127.0.0.1", scope(), ["first"])
        assert store.cancel(queued.id).status == JobStatus.CANCELLED
        job = store.enqueue("127.0.0.1", scope(), ["first", "second"])
    second = FakeScanner()
    AssessmentWorker(
        database, scanners={"first": FakeScanner(cancel=(database, job.id)), "second": second}
    ).run_once()
    with JobStore(database) as store:
        result = store.get_job(job.id)
        assert result.status == JobStatus.CANCELLED
        assert [run.status for run in result.scanner_runs] == [
            JobStatus.SUCCEEDED,
            JobStatus.CANCELLED,
        ]
    assert second.calls == 0


def test_exclusive_lease_and_restart_recovery(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    with JobStore(database) as store:
        job = store.enqueue("127.0.0.1", scope(), ["fake"])
        store.acquire_lease("dead-worker")
        claimed = store.claim_next("dead-worker")
        store.start_run(claimed.scanner_runs[0].id)
        with pytest.raises(WorkerBusyError):
            store.acquire_lease("second-worker")
        store.connection.execute(
            "UPDATE worker_lease SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = 1"
        )
        store.connection.commit()
    fake = FakeScanner()
    AssessmentWorker(database, scanners={"fake": fake}).run_once()
    with JobStore(database) as store:
        assert store.get_job(job.id).status == JobStatus.SUCCEEDED
    assert fake.calls == 1


def test_legacy_scanner_runs_survive_migration(tmp_path: Path) -> None:
    from vaptforge.persistence.migrations import MIGRATIONS

    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    for migration in MIGRATIONS[:2]:
        connection.executescript(migration.sql)
    connection.execute("PRAGMA user_version = 2")
    connection.execute(
        """INSERT INTO assessments VALUES
        ('assessment', 'old', 'lab', '127.0.0.1', '2026-01-01', '2026-01-01')"""
    )
    connection.execute(
        """INSERT INTO scanner_runs
        (id, assessment_id, scanner, target, status, started_at)
        VALUES ('old', 'assessment', 'nmap', '127.0.0.1', 'succeeded', '2026-01-01')"""
    )
    connection.commit()
    connection.close()
    with JobStore(database) as store:
        row = store.connection.execute("SELECT * FROM scanner_runs WHERE id = 'old'").fetchone()
        assert row["scanner"] == "nmap"
        assert row["job_id"] is None


def test_api_queue_auth_scope_progress_and_cancel(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "jobs.db"
    monkeypatch.setattr("vaptforge.api.main.discover_scanners", lambda: {"fake": FakeScanner()})
    client = TestClient(create_app(database_path=database, api_key="secret"))
    payload = {
        "target": "127.0.0.1",
        "scope": scope().model_dump(mode="json"),
        "scanners": ["fake"],
    }
    assert client.post("/api/jobs", json=payload).status_code == 401
    auth = {"X-VAPTForge-API-Key": "secret"}
    assert (
        client.post(
            "/api/jobs", json={**payload, "target": "example.org"}, headers=auth
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/jobs", json={**payload, "scanners": ["unknown"]}, headers=auth
        ).status_code
        == 422
    )
    queued = client.post("/api/jobs", json=payload, headers=auth)
    assert queued.status_code == 202
    job = queued.json()
    assert client.get(f"/api/jobs/{job['id']}").json()["status"] == "queued"
    assert "fake" in client.get(f"/dashboard/assessments/{job['assessment_id']}").text
    assert client.post(f"/api/jobs/{job['id']}/cancel").status_code == 401
    assert (
        client.post(f"/api/jobs/{job['id']}/cancel", headers=auth).json()["status"] == "cancelled"
    )


def test_recovery_reuses_completed_runs(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    with JobStore(database) as store:
        job = store.enqueue("127.0.0.1", scope(), ["first", "second"])
        store.acquire_lease("dead-worker")
        store.claim_next("dead-worker")
        first, second = job.scanner_runs
        store.start_run(first.id)
        store.finish_run(first.id, JobStatus.SUCCEEDED, FakeScanner().scan(job.target, scope()))
        store.start_run(second.id)
        store.connection.execute(
            "UPDATE worker_lease SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = 1"
        )
        store.connection.commit()
    never_again, retry = FakeScanner(), FakeScanner()
    AssessmentWorker(database, scanners={"first": never_again, "second": retry}).run_once()
    with JobStore(database) as store:
        result = store.get_job(job.id)
        assert result.status == JobStatus.SUCCEEDED
        assert [run.finding_count for run in result.scanner_runs] == [1, 1]
        assert len(store.list_findings(job.assessment_id)) == 1
    assert never_again.calls == 0
    assert retry.calls == 1


def test_cli_queue_and_status(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from vaptforge.cli import app

    database, scope_file = tmp_path / "jobs.db", tmp_path / "scope.json"
    scope_file.write_text(scope().model_dump_json(), encoding="utf-8")
    runner = CliRunner()
    queued = runner.invoke(
        app,
        [
            "queue-assessment",
            "127.0.0.1",
            "--scope",
            str(scope_file),
            "--scanners",
            "http",
            "--db",
            str(database),
        ],
    )
    assert queued.exit_code == 0, queued.output
    with JobStore(database) as store:
        job = store.list_jobs()[0]
    status = runner.invoke(app, ["job-status", job.id, "--db", str(database)])
    assert status.exit_code == 0
    assert "http: queued" in status.output
    denied = runner.invoke(
        app, ["queue-assessment", "example.org", "--scope", str(scope_file), "--db", str(database)]
    )
    assert denied.exit_code != 0
