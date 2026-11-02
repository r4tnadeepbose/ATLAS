"""Adapter base class for external security tooling.

Every adapter invokes the tool with an argument list (never ``shell=True``),
enforces a timeout, validates the target, and reports ``available: false``
when the binary is not installed instead of fabricating results.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

from app.config import settings


class AdapterUnavailable(RuntimeError):
    pass


class AdapterError(RuntimeError):
    pass


_SAFE_TARGET = re.compile(r"^[A-Za-z0-9._:/@\[\]-]{1,500}$")


def validate_target(target: str) -> str:
    if not target or target.startswith("-") or not _SAFE_TARGET.match(target):
        raise AdapterError("Target contains characters that are not permitted")
    return target


@dataclass
class ToolAdapter:
    key: str
    binary: str
    category: str
    capabilities: list[str]

    def version(self) -> str | None:
        path = shutil.which(self.binary)
        if not path:
            return None
        try:
            result = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=10, shell=False, check=False
            )
            output = (result.stdout or result.stderr).strip()
            if not output:
                return None
            match = re.search(r"\bv?(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?)", output)
            if match:
                return match.group(1)
            return output.splitlines()[0][:60]
        except (OSError, subprocess.SubprocessError):
            return None

    def availability(self) -> dict:
        path = shutil.which(self.binary)
        return {
            "key": self.key,
            "binary": self.binary,
            "category": self.category,
            "capabilities": self.capabilities,
            "available": path is not None,
            "path": path,
            "version": self.version() if path else None,
        }

    def run(self, args: list[str], *, timeout: int | None = None, stdin_data: str | None = None) -> subprocess.CompletedProcess:
        path = shutil.which(self.binary)
        if not path:
            raise AdapterUnavailable(f"{self.binary} is not installed on this host")
        effective_timeout = min(timeout or settings.scanner_timeout_seconds, settings.scanner_timeout_seconds)
        try:
            return subprocess.run(
                [path, *args],
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                shell=False,
                check=False,
                input=stdin_data,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"{self.key} timed out after {effective_timeout}s") from exc
        except OSError as exc:
            raise AdapterError(f"{self.key} could not be executed: {exc}") from exc
