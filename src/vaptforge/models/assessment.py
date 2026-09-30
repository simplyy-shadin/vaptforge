from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from vaptforge.models.finding import Finding, FindingStatus


class AssessmentRecord(BaseModel):
    id: str
    name: str
    authorization_reference: str
    target: str
    created_at: datetime
    updated_at: datetime


class StoredFinding(BaseModel):
    id: str
    assessment_id: str
    finding: Finding
    created_at: datetime
    updated_at: datetime


class StatusHistoryRecord(BaseModel):
    old_status: FindingStatus
    new_status: FindingStatus
    note: str | None = None
    changed_at: datetime


class ValidationNoteRecord(BaseModel):
    note: str
    created_at: datetime
