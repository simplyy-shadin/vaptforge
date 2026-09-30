from __future__ import annotations

from html import escape

from vaptforge.models.assessment import AssessmentRecord, RetestRunRecord, StoredFinding
from vaptforge.persistence.jobs import AssessmentJob
from vaptforge.reporting.metrics import finding_metrics, retest_metrics

STYLE = """
body { font-family: Arial, sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }
header { background: #0f172a; color: white; padding: 22px 32px; }
main { max-width: 1180px; margin: 28px auto; padding: 0 20px; }
a { color: #2563eb; text-decoration: none; }
table { width: 100%; border-collapse: collapse; background: white; margin: 18px 0 30px; }
th, td { text-align: left; border-bottom: 1px solid #e2e8f0; padding: 10px; vertical-align: top; }
th { background: #f1f5f9; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 18px 0; }
.card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 18px; }
.badge { display: inline-block; border-radius: 999px; padding: 3px 9px; background: #e2e8f0; }
.actions a { margin-right: 12px; }
.evidence { color: #475569; font-size: 0.92rem; }
code { background: #e2e8f0; padding: 2px 5px; border-radius: 4px; }
"""


def _page(title: str, content: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title>
<style>{STYLE}</style>
</head>
<body>
<header><strong>VAPTForge</strong> - Authorized Assessment Console</header>
<main>{content}</main>
</body>
</html>
"""


def render_dashboard(
    assessments: list[AssessmentRecord],
    retests: list[RetestRunRecord],
) -> str:
    assessment_rows = "".join(
        f"""<tr>
<td><a href="/dashboard/assessments/{escape(item.id)}">{escape(item.name)}</a></td>
<td><code>{escape(item.target)}</code></td>
<td>{escape(item.updated_at.isoformat(timespec="seconds"))}</td>
</tr>"""
        for item in assessments
    )
    retest_rows = "".join(
        f"""<tr>
<td><code>{escape(item.id)}</code></td>
<td><a href="/dashboard/assessments/{escape(item.before_assessment_id)}">
{escape(item.before_assessment_id)}</a></td>
<td><a href="/dashboard/assessments/{escape(item.after_assessment_id)}">
{escape(item.after_assessment_id)}</a></td>
<td>{retest_metrics(item.results)["fixed"]}</td>
<td>{retest_metrics(item.results)["persistent"]}</td>
<td>{retest_metrics(item.results)["new"]}</td>
</tr>"""
        for item in retests
    )

    content = f"""
<h1>Assessments</h1>
<p>Local read-only dashboard over the persisted VAPT workflow.</p>
<table>
<thead><tr><th>Name</th><th>Target</th><th>Updated</th></tr></thead>
<tbody>{assessment_rows or '<tr><td colspan="3">No assessments yet.</td></tr>'}</tbody>
</table>

<h2>Retest history</h2>
<table>
<thead>
<tr><th>Run</th><th>Before</th><th>After</th><th>Fixed</th><th>Persistent</th><th>New</th></tr>
</thead>
<tbody>{retest_rows or '<tr><td colspan="6">No retest runs yet.</td></tr>'}</tbody>
</table>
"""
    return _page("VAPTForge Dashboard", content)


def render_assessment_dashboard(
    assessment: AssessmentRecord,
    findings: list[StoredFinding],
    jobs: list[AssessmentJob] | None = None,
) -> str:
    metrics = finding_metrics([item.finding for item in findings])
    severity = metrics["severity"]
    cards = [f'<div class="card"><strong>Total</strong><br>{metrics["total"]}</div>']
    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cards.append(
            f'<div class="card"><strong>{label}</strong><br>{severity.get(label, 0)}</div>'
        )

    rows = []
    for stored in findings:
        finding = stored.finding
        evidence = (
            "<br>".join(escape(item.summary) for item in finding.evidence[:3]) or "No evidence"
        )
        rows.append(
            f"""<tr>
<td><code>{escape(stored.id)}</code></td>
<td><span class="badge">{escape(finding.severity.label())}</span></td>
<td>{escape(finding.status.value)}</td>
<td>{escape(finding.title)}</td>
<td><code>{escape(finding.location or "N/A")}</code></td>
<td class="evidence">{evidence}</td>
</tr>"""
        )

    assessment_id = escape(assessment.id)
    job_rows = "".join(
        f"""<tr><td><code>{escape(job.id)}</code></td>
<td>{escape(job.status.value)}</td>
<td>{sum(run.status.value in ("succeeded", "failed", "cancelled") for run in job.scanner_runs)}
 / {len(job.scanner_runs)}</td>
<td>{escape(job.error_message or "")}</td></tr>"""
        for job in jobs or []
    )
    run_rows = "".join(
        f"""<tr><td>{escape(run.scanner)}</td><td>{escape(run.status.value)}</td>
<td>{run.finding_count}</td><td>{escape(run.error_message or "")}</td></tr>"""
        for job in jobs or []
        for run in job.scanner_runs
    )
    content = f"""
<p><a href="/">&larr; All assessments</a></p>
<h1>{escape(assessment.name)}</h1>
<p><strong>Target:</strong> <code>{escape(assessment.target)}</code></p>
<div class="cards">{"".join(cards)}</div>

<h2>Assessment jobs</h2>
<p>Refresh to see scanner progress. Running scans complete before cancellation takes effect.</p>
<table><thead><tr><th>Job ID</th><th>Status</th><th>Runs completed</th><th>Error</th></tr></thead>
<tbody>{job_rows or '<tr><td colspan="4">No background jobs.</td></tr>'}</tbody></table>
<table><thead><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Error</th></tr></thead>
<tbody>{run_rows or '<tr><td colspan="4">No scanner runs.</td></tr>'}</tbody></table>

<div class="actions">
<strong>Exports:</strong>
<a href="/api/assessments/{assessment_id}/report/markdown">Markdown</a>
<a href="/api/assessments/{assessment_id}/report/json">JSON</a>
<a href="/api/assessments/{assessment_id}/report/html">HTML</a>
<a href="/api/assessments/{assessment_id}/report/pdf">PDF</a>
</div>

<h2>Findings</h2>
<form method="get">
<label>Severity
<select name="severity">
<option value="">All</option>
<option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option>
<option>LOW</option><option>INFO</option>
</select>
</label>
<label>Status
<select name="status">
<option value="">All</option>
<option>discovered</option><option>potential</option><option>verified</option>
<option>remediated</option><option>retested</option><option>false_positive</option>
</select>
</label>
<button type="submit">Filter</button>
<a href="/dashboard/assessments/{assessment_id}">Clear</a>
</form>
<table>
<thead>
<tr><th>ID</th><th>Severity</th><th>Status</th><th>Title</th><th>Location</th><th>Evidence</th></tr>
</thead>
<tbody>{"".join(rows) or '<tr><td colspan="6">No findings.</td></tr>'}</tbody>
</table>
"""
    return _page(f"Assessment - {assessment.name}", content)
