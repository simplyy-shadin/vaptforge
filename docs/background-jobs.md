# Background assessments (v0.7)

VAPTForge keeps the existing synchronous `scan` command. Background assessments use a SQLite queue and a **separate local worker**. Starting the API alone does not execute scans, and no job is created by starting the worker.

## Local workflow

In one terminal:

```bash
vaptforge worker --db data/vaptforge.db
```

In another:

```bash
vaptforge queue-assessment http://127.0.0.1:3000 \
  --scope config/scope.example.json --scanners http,tls \
  --db data/vaptforge.db
vaptforge job-status <JOB_ID> --db data/vaptforge.db
```

`vaptforge worker --once` processes at most one queued job and exits. The API and worker must use the same database path. Start the dashboard with `VAPTFORGE_DB=data/vaptforge.db` to see assessment and per-scanner status.

The queue stores a snapshot of the supplied scope, authorization reference, target, and ordered scanner names. It checks the target before inserting a job. The worker checks scope again immediately before each scanner invocation. Plugins receive the same `AuthorizedScope` contract as built-in scanners. A plugin may be missing when the worker starts; that run fails independently, with the reason recorded.

Scanner runs transition `queued → running → succeeded/failed/cancelled`. Jobs transition `queued → running → succeeded/failed/cancelled`. A scanner failure does not stop subsequent scanners. Successful scanner output is stored per run; after the last scanner, findings are correlated, enriched, and saved to the assessment. A job is `failed` if any scanner fails, and successful findings remain available. Scanner observations retain their discovery status until manual validation.

## API

With `VAPTFORGE_API_KEY` configured, create a job:

```bash
curl -X POST http://127.0.0.1:8000/api/jobs \
  -H "X-VAPTForge-API-Key: $VAPTFORGE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"target":"http://127.0.0.1:3000","scope":{"assessment_name":"Local lab","authorization_reference":"Owned lab","targets":[{"value":"127.0.0.1"}]},"scanners":["http","tls"]}'
```

`GET /api/jobs`, `GET /api/jobs/{job_id}`, and the assessment dashboard show progress. `POST /api/jobs/{job_id}/cancel` requires the API key. Queued jobs cancel immediately. A running job checks cancellation after its active scanner returns, before starting the next one. Existing scanner adapters use blocking calls, so there is no mid-scanner termination in this milestone.

## Recovery and limits

Only one worker can hold the database lease at a time. It renews the lease while a scan runs. If a worker stops unexpectedly, a new worker waits for the lease to expire (up to about 45 seconds), then requeues interrupted runs. Completed scanner results are reused. An interrupted scanner may run again, so use scanners that are safe to repeat. A crashed worker may have stopped after the target received a request but before results were saved.

The worker and SQLite file belong on the same local host. This is a portfolio-scale local queue, not a distributed scheduler. Keep the dashboard bound to loopback unless you add network authentication and access controls. The queued scope contains assessment metadata; protect the database file accordingly. A future `vaptforge start` command can supervise the worker and API, but this release does not include it.
