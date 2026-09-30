from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class ScopeEntry(BaseModel):
    value: str
    description: str | None = None

    @field_validator("value")
    @classmethod
    def non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("scope entry cannot be empty")
        return value


class AuthorizedScope(BaseModel):
    assessment_name: str
    authorization_reference: str
    targets: list[ScopeEntry] = Field(min_length=1)

    @classmethod
    def from_json_file(cls, path: str | Path) -> AuthorizedScope:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)

    @staticmethod
    def _candidate_host(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"//{target}")
        host = parsed.hostname
        return host or target.split(":", maxsplit=1)[0].strip("[]")

    @staticmethod
    def _host_matches_entry(host: str, entry: str) -> bool:
        entry_value = entry.strip()
        parsed_entry = urlparse(entry_value) if "://" in entry_value else None
        if parsed_entry and parsed_entry.hostname:
            entry_value = parsed_entry.hostname

        try:
            candidate_ip = ipaddress.ip_address(host)
        except ValueError:
            candidate_ip = None

        try:
            network = ipaddress.ip_network(entry_value, strict=False)
        except ValueError:
            network = None

        if candidate_ip is not None and network is not None:
            return candidate_ip in network

        if candidate_ip is not None:
            try:
                return candidate_ip == ipaddress.ip_address(entry_value)
            except ValueError:
                return False

        normalized_host = host.rstrip(".").lower()
        normalized_entry = entry_value.rstrip(".").lower()
        return normalized_host == normalized_entry

    def is_authorized(self, target: str) -> bool:
        host = self._candidate_host(target)
        return any(self._host_matches_entry(host, item.value) for item in self.targets)

    def require_authorized(self, target: str) -> None:
        if not self.is_authorized(target):
            raise PermissionError(
                f"Target '{target}' is not present in the authorized scope. "
                "Add it to the scope file only after confirming permission to test it."
            )
