from __future__ import annotations

import os
import subprocess
import sys
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from time import sleep

import httpx

from vaptforge.persistence.store import AssessmentStore


@dataclass(frozen=True)
class PlatformCommands:
    worker: tuple[str, ...]
    api: tuple[str, ...]


def build_platform_commands(
    database: Path,
    *,
    host: str,
    port: int,
) -> PlatformCommands:
    python = sys.executable
    return PlatformCommands(
        worker=(
            python,
            "-m",
            "vaptforge.cli",
            "worker",
            "--db",
            str(database),
        ),
        api=(
            python,
            "-m",
            "uvicorn",
            "vaptforge.api.main:app",
            "--host",
            host,
            "--port",
            str(port),
        ),
    )


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_platform(
    database: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = True,
) -> None:
    database.parent.mkdir(parents=True, exist_ok=True)
    with AssessmentStore(database):
        pass

    commands = build_platform_commands(database, host=host, port=port)
    env = os.environ.copy()
    env["VAPTFORGE_DB"] = str(database)

    worker = subprocess.Popen(commands.worker, env=env)
    api = subprocess.Popen(commands.api, env=env)
    url = f"http://{host}:{port}/"

    try:
        for _ in range(30):
            if api.poll() is not None:
                raise RuntimeError("VAPTForge API stopped during startup")
            try:
                response = httpx.get(f"http://{host}:{port}/health", timeout=0.25)
                if response.status_code == 200:
                    break
            except httpx.HTTPError:
                sleep(0.1)
        else:
            raise RuntimeError("VAPTForge API did not become ready")

        if open_browser:
            webbrowser.open(url)

        while True:
            if api.poll() is not None:
                raise RuntimeError(f"VAPTForge API exited with code {api.returncode}")
            if worker.poll() is not None:
                raise RuntimeError(f"VAPTForge worker exited with code {worker.returncode}")
            sleep(1)
    except KeyboardInterrupt:
        return
    finally:
        _terminate(api)
        _terminate(worker)
