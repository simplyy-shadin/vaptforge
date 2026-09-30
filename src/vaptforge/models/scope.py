from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
BLOCKED_SESSION_HEADERS = {"host", "content-length", "transfer-encoding"}


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


class SessionAuth(BaseModel):
    """References authentication values through environment variables only."""

    cookie_env: str | None = None
    authorization_env: str | None = None
    headers_env: dict[str, str] = Field(default_factory=dict)

    @field_validator("cookie_env", "authorization_env")
    @classmethod
    def valid_optional_env_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not ENV_NAME_RE.fullmatch(value):
            raise ValueError(
                "session environment variable names must be valid shell variable names"
            )
        return value

    @field_validator("headers_env")
    @classmethod
    def valid_header_environment_map(cls, value: dict[str, str]) -> dict[str, str]:
        cleaned: dict[str, str] = {}
        for header, env_name in value.items():
            header = header.strip()
            env_name = env_name.strip()
            if not HEADER_NAME_RE.fullmatch(header):
                raise ValueError(f"invalid HTTP header name: {header}")
            if header.lower() in BLOCKED_SESSION_HEADERS:
                raise ValueError(f"session header cannot override {header}")
            if not ENV_NAME_RE.fullmatch(env_name):
                raise ValueError(
                    "session environment variable names must be valid shell variable names"
                )
            cleaned[header] = env_name
        return cleaned

    @model_validator(mode="after")
    def require_reference(self) -> SessionAuth:
        if not self.cookie_env and not self.authorization_env and not self.headers_env:
            raise ValueError(
                "session configuration must reference at least one environment variable"
            )
        return self

    def environment_references(self) -> tuple[str, ...]:
        refs = [self.cookie_env, self.authorization_env, *self.headers_env.values()]
        return tuple(dict.fromkeys(item for item in refs if item))


class AuthorizedScope(BaseModel):
    assessment_name: str
    authorization_reference: str
    targets: list[ScopeEntry] = Field(min_length=1)
    session: SessionAuth | None = None

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
