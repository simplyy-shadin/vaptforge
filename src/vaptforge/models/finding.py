from __future__ import annotations

from enum import IntEnum, StrEnum
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, Field


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_text(cls, value: str | None) -> Severity:
        if not value:
            return cls.INFO
        normalized = value.strip().upper()
        return cls.__members__.get(normalized, cls.INFO)

    def label(self) -> str:
        return self.name


class FindingStatus(StrEnum):
    DISCOVERED = "discovered"
    POTENTIAL = "potential"
    VERIFIED = "verified"
    REMEDIATED = "remediated"
    RETESTED = "retested"
    FALSE_POSITIVE = "false_positive"


class Evidence(BaseModel):
    source: str
    summary: str
    raw: str | None = None


class AssetRef(BaseModel):
    target: str
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None


class Finding(BaseModel):
    title: str
    severity: Severity = Severity.INFO
    asset: AssetRef
    source: str
    status: FindingStatus = FindingStatus.DISCOVERED
    description: str | None = None
    location: str | None = None
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        cve_key = ",".join(sorted(self.cves))
        raw = "|".join(
            [
                self.title.strip().lower(),
                (self.asset.host or self.asset.target).strip().lower(),
                str(self.asset.port or ""),
                (self.location or "").strip().lower(),
                cve_key.lower(),
            ]
        )
        return sha256(raw.encode("utf-8")).hexdigest()[:16]
