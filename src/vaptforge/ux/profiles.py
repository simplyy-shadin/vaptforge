from __future__ import annotations

from dataclasses import dataclass

from vaptforge.ux.tooling import probe_scanner_tool


@dataclass(frozen=True)
class AssessmentProfile:
    name: str
    label: str
    description: str
    scanners: tuple[str, ...]


PROFILES: dict[str, AssessmentProfile] = {
    "quick": AssessmentProfile(
        name="quick",
        label="Quick",
        description="Fast built-in HTTP and TLS checks with no optional scanner binaries required.",
        scanners=("http", "tls"),
    ),
    "web": AssessmentProfile(
        name="web",
        label="Web",
        description="Web-focused assessment: HTTP/TLS plus discovery and web scanners.",
        scanners=("http", "tls", "httpx", "nikto", "nuclei", "ffuf"),
    ),
    "network": AssessmentProfile(
        name="network",
        label="Network",
        description="Host/service discovery and safe network-oriented checks.",
        scanners=("nmap", "nuclei"),
    ),
    "full": AssessmentProfile(
        name="full",
        label="Full",
        description="All baseline web and network scanners for an authorized assessment target.",
        scanners=("http", "tls", "httpx", "nmap", "nikto", "nuclei", "ffuf"),
    ),
    "deep": AssessmentProfile(
        name="deep",
        label="Deep",
        description=(
            "Bounded attack-surface crawling plus safe native parameter analysis and the full "
            "scanner stack. No brute force, destructive checks, or automatic exploitation."
        ),
        scanners=(
            "http",
            "tls",
            "deep-web",
            "httpx",
            "nmap",
            "nikto",
            "nuclei",
            "ffuf",
        ),
    ),
}

def profile_names() -> tuple[str, ...]:
    return tuple(PROFILES)


def get_profile(name: str) -> AssessmentProfile:
    normalized = name.strip().lower()
    try:
        return PROFILES[normalized]
    except KeyError as exc:
        raise ValueError(
            f"Unknown profile '{name}'. Choose one of: {', '.join(PROFILES)}"
        ) from exc


def resolve_profile_scanners(
    name: str,
    *,
    registered: set[str],
    skip_unavailable: bool = True,
) -> tuple[list[str], list[str]]:
    profile = get_profile(name)
    selected: list[str] = []
    skipped: list[str] = []

    for scanner in profile.scanners:
        if scanner not in registered:
            skipped.append(f"{scanner} (not registered)")
            continue
        if skip_unavailable:
            probe = probe_scanner_tool(scanner)
            if not probe.available:
                skipped.append(f"{scanner} ({probe.detail})")
                continue
        selected.append(scanner)

    return selected, skipped
