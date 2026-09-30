# API and Dashboard

VAPTForge v0.5 exposes the persisted assessment model through a local FastAPI application.

## Start the console

```bash
export VAPTFORGE_DB=data/vaptforge.db
uvicorn vaptforge.api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/`.

The dashboard provides:

- assessment summaries
- severity/status filtering
- evidence previews
- report export controls
- retest history

## Read API

Read endpoints do not mutate assessment state:

```text
GET /health
GET /api/assessments
GET /api/assessments/{assessment_id}
GET /api/assessments/{assessment_id}/findings
GET /api/findings/{finding_id}
GET /api/retests
GET /api/retests/compare/{before_id}/{after_id}
GET /api/assessments/{assessment_id}/report/{format}
GET /api/retests/{retest_id}/report
```

Finding filters:

```text
?severity=HIGH&status=verified
```

Report formats:

```text
markdown
json
html
pdf
```

## Mutation security

API writes are disabled unless an API key is configured:

```bash
export VAPTFORGE_API_KEY="replace-with-a-long-random-value"
```

Mutation requests must send:

```text
X-VAPTForge-API-Key: <configured key>
```

Write endpoints:

```text
POST /api/findings/{finding_id}/transition
POST /api/findings/{finding_id}/notes
POST /api/findings/{finding_id}/evidence
```

If no API key is set, these endpoints return HTTP 403 and the CLI remains the write interface. Incorrect keys return HTTP 401. Key comparison uses `secrets.compare_digest`.

## Deployment boundary

The dashboard is designed primarily as a local assessment console. The recommended development command binds to `127.0.0.1`. If it is placed behind a network-facing reverse proxy, add normal production controls such as TLS, authentication, authorization, request logging, rate limiting, and network restrictions.
