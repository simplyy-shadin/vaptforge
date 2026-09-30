from __future__ import annotations

from abc import ABC, abstractmethod

from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope


class Scanner(ABC):
    name: str

    @abstractmethod
    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        """Scan an explicitly authorized target and return normalized findings."""
        raise NotImplementedError
