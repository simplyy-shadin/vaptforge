from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolProbe:
    name: str
    available: bool
    detail: str
    path: str | None = None


SCANNER_BINARIES: dict[str, str] = {
    "httpx": "httpx",
    "nmap": "nmap",
    "nikto": "nikto",
    "nuclei": "nuclei",
    "ffuf": "ffuf",
}


def _probe_projectdiscovery_httpx(path: str) -> ToolProbe:
    try:
        completed = subprocess.run(
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolProbe(
            name="httpx",
            available=False,
            detail=f"unable to verify ProjectDiscovery httpx: {type(exc).__name__}",
            path=path,
        )

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode != 0:
        hint = "wrong httpx executable; ProjectDiscovery httpx is required"
        if "No such option" in output or "Usage: httpx [OPTIONS] URL" in output:
            hint = "Python httpx CLI detected; install ProjectDiscovery httpx"
        return ToolProbe(name="httpx", available=False, detail=hint, path=path)

    return ToolProbe(
        name="httpx",
        available=True,
        detail="ProjectDiscovery httpx verified",
        path=path,
    )


def probe_scanner_tool(scanner: str) -> ToolProbe:
    binary = SCANNER_BINARIES.get(scanner)
    if binary is None:
        return ToolProbe(name=scanner, available=True, detail="built-in scanner")

    path = shutil.which(binary)
    if path is None:
        return ToolProbe(name=scanner, available=False, detail="tool not installed")

    if scanner == "httpx":
        return _probe_projectdiscovery_httpx(path)

    return ToolProbe(name=scanner, available=True, detail="available", path=path)
