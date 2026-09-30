"""Single local worker with a renewable SQLite lease and scanner isolation."""

from __future__ import annotations

import logging
import threading
import uuid
from pathlib import Path
from time import sleep

from vaptforge.correlation.engine import correlate_findings
from vaptforge.enrichment.owasp import enrich_owasp
from vaptforge.persistence.jobs import JobStatus, JobStore, WorkerBusyError
from vaptforge.scanners.base import Scanner
from vaptforge.scanners.registry import discover_scanners

logger = logging.getLogger(__name__)


class AssessmentWorker:
    def __init__(self, database: str | Path, *, scanners: dict[str, Scanner] | None = None) -> None:
        self.database = Path(database)
        self.scanners = scanners if scanners is not None else discover_scanners()
        self.owner = str(uuid.uuid4())
        self._stop = threading.Event()
        self._lost_lease = threading.Event()

    def _heartbeat(self) -> None:
        while not self._stop.wait(10):
            try:
                with JobStore(self.database) as store:
                    if not store.renew_lease(self.owner):
                        self._lost_lease.set()
                        return
            except Exception:
                # A temporary SQLite lock may resolve before the lease expires.
                logger.exception("Worker lease renewal failed")
                continue

    def _require_lease(self, store: JobStore) -> None:
        if self._lost_lease.is_set() or not store.owns_lease(self.owner):
            raise WorkerBusyError("Worker lease lost; refusing to persist scanner output")

    def _process(self, store: JobStore, job_id: str) -> None:
        job = store.get_job(job_id)
        if job is None:
            raise RuntimeError("Claimed job disappeared")
        errors: list[str] = []
        for run in job.scanner_runs:
            self._require_lease(store)
            current = store.get_job(job_id)
            if current is None:
                raise RuntimeError("Running job disappeared")
            if current.cancel_requested:
                store.finish_job(job_id, JobStatus.CANCELLED)
                return
            if run.status == JobStatus.SUCCEEDED:
                continue
            if run.status == JobStatus.FAILED:
                errors.append(f"{run.scanner}: {run.error_message}")
                continue
            store.start_run(run.id)
            try:
                current.scope.require_authorized(current.target)
                scanner = self.scanners[run.scanner]
                findings = scanner.scan(current.target, current.scope)
                self._require_lease(store)
                store.finish_run(run.id, JobStatus.SUCCEEDED, findings)
            except WorkerBusyError:
                raise
            except Exception as exc:
                self._require_lease(store)
                error = f"{type(exc).__name__}: {exc}"[:1000]
                store.finish_run(run.id, JobStatus.FAILED, error=error)
                errors.append(f"{run.scanner}: {error}")

        self._require_lease(store)
        current = store.get_job(job_id)
        if current is None:
            raise RuntimeError("Running job disappeared")
        if current.cancel_requested:
            store.finish_job(job_id, JobStatus.CANCELLED)
            return
        findings = [enrich_owasp(item) for item in correlate_findings(store.results(job_id))]
        store.save_findings(job.assessment_id, findings)
        store.finish_job(
            job_id,
            JobStatus.FAILED if errors else JobStatus.SUCCEEDED,
            "; ".join(errors)[:2000] if errors else None,
        )

    def run_once(self) -> str | None:
        """Claim and process one job. Returns its ID, or None when the queue is empty."""
        self._stop.clear()
        self._lost_lease.clear()
        with JobStore(self.database) as store:
            store.acquire_lease(self.owner)
            heartbeat = threading.Thread(target=self._heartbeat, daemon=True)
            heartbeat.start()
            try:
                job = store.claim_next(self.owner)
                if job is None:
                    return None
                try:
                    self._process(store, job.id)
                except WorkerBusyError:
                    raise
                except Exception as exc:
                    self._require_lease(store)
                    store.finish_job(
                        job.id,
                        JobStatus.FAILED,
                        f"Orchestration error: {type(exc).__name__}: {exc}"[:2000],
                    )
                return job.id
            finally:
                self._stop.set()
                heartbeat.join(timeout=15)
                store.release_lease(self.owner)

    def run_forever(self, poll_interval: float = 2.0) -> None:
        """Poll for work; each job gets a fresh lease and recovery check."""
        while True:
            if self.run_once() is None:
                sleep(poll_interval)
