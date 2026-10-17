"""Opt-in Windows Packet Monitor capture-to-PCAPNG research prototype.

The prototype deliberately is not wired into CaptureSession. It demonstrates
safe argument construction and a bounded capture artifact lifecycle for parity
experiments; it is not a production live-streaming backend.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Callable, Mapping, Sequence


class PktmonPrototypeError(RuntimeError):
    """Raised when the research backend is unavailable or a command fails."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


class PktmonCapturePrototype:
    """Own one explicit Pktmon capture and convert it after stopping."""

    def __init__(
        self,
        *,
        executable: str | None = None,
        runner: Runner = subprocess.run,
        system_name: str | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.system_name = system_name or platform.system()
        self.environ = environ or os.environ
        self.executable = executable or shutil.which("pktmon")
        self.runner = runner
        self.etl_path: Path | None = None
        self.started = False

    def _require_available(self) -> None:
        enabled = self.environ.get("NSCOUT_EXPERIMENTAL_PKTMON", "").lower() in {
            "1", "true", "yes", "on"
        }
        if not enabled:
            raise PktmonPrototypeError("Pktmon research mode is disabled")
        if self.system_name != "Windows" or not self.executable:
            raise PktmonPrototypeError("Pktmon is available only on supported Windows systems")

    def _run(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        result = self.runner(
            [str(self.executable), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            message = (result.stderr or result.stdout or "Pktmon command failed").strip()
            raise PktmonPrototypeError(message)
        return result

    def start(self, directory: Path, *, max_megabytes: int = 256) -> Path:
        """Start a circular full-packet NIC capture owned by this object."""
        self._require_available()
        if self.started:
            raise PktmonPrototypeError("This prototype capture is already running")
        if not 16 <= max_megabytes <= 2048:
            raise ValueError("max_megabytes must be between 16 and 2048")
        directory.mkdir(parents=True, exist_ok=True)
        self.etl_path = directory / f"nscout-pktmon-{uuid.uuid4().hex}.etl"
        self._run(
            [
                "start", "--capture", "--comp", "nics", "--pkt-size", "0",
                "--file-name", str(self.etl_path), "--file-size", str(max_megabytes),
                "--log-mode", "circular",
            ]
        )
        self.started = True
        return self.etl_path

    def stop_and_convert(self) -> Path:
        """Stop the owned capture and convert its ETL artifact to PCAPNG."""
        if not self.started or self.etl_path is None:
            raise PktmonPrototypeError("No prototype capture is running")
        try:
            self._run(["stop"])
        finally:
            self.started = False
        pcapng_path = self.etl_path.with_suffix(".pcapng")
        self._run(["etl2pcap", str(self.etl_path), "--out", str(pcapng_path)])
        return pcapng_path
