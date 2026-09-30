from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel

from vaptforge import __version__
from vaptforge.api.dashboard import render_assessment_dashboard, render_dashboard
from vaptforge.models.finding import Evidence, FindingStatus
from vaptforge.persistence.store import AssessmentStore, InvalidStatusTransition
from vaptforge.reporting.html import render_html_report
from vaptforge.reporting.markdown import render_markdown_report
from vaptforge.reporting.metrics import finding_metrics
from vaptforge.reporting.pdf import render_pdf_bytes
from vaptforge.reporting.retest_markdown import render_retest_markdown
from vaptforge.retest.engine import compare_findings

ApiKeyHeader = Annotated[str | None, Header(alias="X-VAPTForge-API-Key")]
FilterValue = Annotated[str | None, Query()]


class TransitionRequest(BaseModel):
    status: FindingStatus
    note: str | None = None


class NoteRequest(BaseModel):
    note: str


class EvidenceRequest(BaseModel):
    source: str = "manual"
    summary: str
    attachment_path: str | None = None


def create_app(
    database_path: str | Path | None = None,
    api_key: str | None = None,
) -> FastAPI:
    application = FastAPI(
        title="VAPTForge API",
        version=__version__,
        description="Local API for persisted authorized VAPT assessments.",
    )
    application.state.database_path = Path(
        database_path or os.getenv("VAPTFORGE_DB", "vaptforge.db")
    )
    application.state.api_key = (
        api_key if api_key is not None else os.getenv("VAPTFORGE_API_KEY")
    )

    def require_write_access(x_api_key: ApiKeyHeader = None) -> None:
        configured = application.state.api_key
        if not configured:
            raise HTTPException(
                status_code=403,
                detail=(
                    "API mutations are disabled. Set VAPTFORGE_API_KEY or use the CLI."
                ),
            )
        if x_api_key is None or not secrets.compare_digest(x_api_key, configured):
            raise HTTPException(status_code=401, detail="Invalid API key")

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @application.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        with AssessmentStore(application.state.database_path) as store:
            return render_dashboard(store.list_assessments(), store.list_retests())

    @application.get("/dashboard/assessments/{assessment_id}", response_class=HTMLResponse)
    def assessment_dashboard(
        assessment_id: str,
        severity: FilterValue = None,
        status: FilterValue = None,
    ) -> str:
        with AssessmentStore(application.state.database_path) as store:
            assessment = store.get_assessment(assessment_id)
            if assessment is None:
                raise HTTPException(status_code=404, detail="Assessment not found")
            findings = store.list_findings(assessment_id)

        normalized_severity = severity.upper() if severity else None
        normalized_status = status.lower() if status else None
        filtered = [
            item
            for item in findings
            if (
                normalized_severity is None
                or item.finding.severity.label() == normalized_severity
            )
            and (
                normalized_status is None
                or item.finding.status.value == normalized_status
            )
        ]
        return render_assessment_dashboard(assessment, filtered)

    @application.get("/api/assessments")
    def assessments() -> list[dict[str, object]]:
        with AssessmentStore(application.state.database_path) as store:
            return [
                item.model_dump(mode="json")
                for item in store.list_assessments()
            ]

    @application.get("/api/assessments/{assessment_id}")
    def assessment_detail(assessment_id: str) -> dict[str, object]:
        with AssessmentStore(application.state.database_path) as store:
            assessment = store.get_assessment(assessment_id)
            if assessment is None:
                raise HTTPException(status_code=404, detail="Assessment not found")
            findings = store.list_findings(assessment_id)
        return {
            "assessment": assessment.model_dump(mode="json"),
            "metrics": finding_metrics([item.finding for item in findings]),
        }

    @application.get("/api/assessments/{assessment_id}/findings")
    def assessment_findings(
        assessment_id: str,
        severity: FilterValue = None,
        status: FilterValue = None,
    ) -> list[dict[str, object]]:
        with AssessmentStore(application.state.database_path) as store:
            if store.get_assessment(assessment_id) is None:
                raise HTTPException(status_code=404, detail="Assessment not found")
            findings = store.list_findings(assessment_id)

        normalized_severity = severity.upper() if severity else None
        normalized_status = status.lower() if status else None
        filtered = [
            item
            for item in findings
            if (normalized_severity is None or item.finding.severity.label() == normalized_severity)
            and (normalized_status is None or item.finding.status.value == normalized_status)
        ]
        return [item.model_dump(mode="json") for item in filtered]

    @application.get("/api/findings/{finding_id}")
    def finding_detail(finding_id: str) -> dict[str, object]:
        with AssessmentStore(application.state.database_path) as store:
            finding = store.get_finding(finding_id)
            if finding is None:
                raise HTTPException(status_code=404, detail="Finding not found")
            notes = store.list_validation_notes(finding_id)
            history = store.status_history(finding_id)
        return {
            "finding": finding.model_dump(mode="json"),
            "validation_notes": [item.model_dump(mode="json") for item in notes],
            "status_history": [item.model_dump(mode="json") for item in history],
        }

    @application.post("/api/findings/{finding_id}/transition")
    def transition_finding(
        finding_id: str,
        request: TransitionRequest,
        _write_access: None = Depends(require_write_access),
    ) -> dict[str, str]:
        try:
            with AssessmentStore(application.state.database_path) as store:
                store.transition_finding(
                    finding_id,
                    request.status,
                    note=request.note,
                )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except InvalidStatusTransition as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "updated", "finding_id": finding_id}

    @application.post("/api/findings/{finding_id}/notes")
    def add_note(
        finding_id: str,
        request: NoteRequest,
        _write_access: None = Depends(require_write_access),
    ) -> dict[str, str]:
        try:
            with AssessmentStore(application.state.database_path) as store:
                store.add_validation_note(finding_id, request.note)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"status": "created", "finding_id": finding_id}

    @application.post("/api/findings/{finding_id}/evidence")
    def add_evidence(
        finding_id: str,
        request: EvidenceRequest,
        _write_access: None = Depends(require_write_access),
    ) -> dict[str, str]:
        try:
            with AssessmentStore(application.state.database_path) as store:
                store.add_evidence(
                    finding_id,
                    Evidence(
                        source=request.source,
                        summary=request.summary,
                        attachment_path=request.attachment_path,
                    ),
                )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"status": "created", "finding_id": finding_id}

    @application.get("/api/retests")
    def retests() -> list[dict[str, object]]:
        with AssessmentStore(application.state.database_path) as store:
            return [item.model_dump(mode="json") for item in store.list_retests()]

    @application.get("/api/retests/compare/{before_id}/{after_id}")
    def compare_assessments(before_id: str, after_id: str) -> dict[str, object]:
        with AssessmentStore(application.state.database_path) as store:
            if store.get_assessment(before_id) is None:
                raise HTTPException(status_code=404, detail="Baseline assessment not found")
            if store.get_assessment(after_id) is None:
                raise HTTPException(status_code=404, detail="Retest assessment not found")
            before = [item.finding for item in store.list_findings(before_id)]
            after = [item.finding for item in store.list_findings(after_id)]
        results = compare_findings(before, after)
        return {
            "before_assessment_id": before_id,
            "after_assessment_id": after_id,
            "results": [item.model_dump(mode="json") for item in results],
        }

    @application.get("/api/assessments/{assessment_id}/report/{report_format}")
    def assessment_report(assessment_id: str, report_format: str) -> Response:
        with AssessmentStore(application.state.database_path) as store:
            assessment = store.get_assessment(assessment_id)
            if assessment is None:
                raise HTTPException(status_code=404, detail="Assessment not found")
            findings = [item.finding for item in store.list_findings(assessment_id)]

        normalized = report_format.lower()
        if normalized == "markdown":
            return PlainTextResponse(
                render_markdown_report(assessment.name, assessment.target, findings),
                media_type="text/markdown",
            )
        if normalized == "html":
            return HTMLResponse(
                render_html_report(assessment.name, assessment.target, findings)
            )
        if normalized == "json":
            return JSONResponse(
                [item.model_dump(mode="json") for item in findings]
            )
        if normalized == "pdf":
            return Response(
                content=render_pdf_bytes(assessment.name, assessment.target, findings),
                media_type="application/pdf",
                headers={
                    "Content-Disposition": (
                        f'attachment; filename="vaptforge-{assessment_id}.pdf"'
                    )
                },
            )
        raise HTTPException(status_code=404, detail="Unsupported report format")

    @application.get("/api/retests/{retest_id}/report")
    def retest_report(retest_id: str) -> Response:
        with AssessmentStore(application.state.database_path) as store:
            run = next(
                (item for item in store.list_retests() if item.id == retest_id),
                None,
            )
        if run is None:
            raise HTTPException(status_code=404, detail="Retest run not found")
        return PlainTextResponse(
            render_retest_markdown(
                run.before_assessment_id,
                run.after_assessment_id,
                run.results,
            ),
            media_type="text/markdown",
        )

    return application


app = create_app()
