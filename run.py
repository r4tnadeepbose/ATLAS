#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ATLAS Security Orchestration

"""ATLAS one-click launcher.

Double-click run.bat (Windows) or execute this file to:
  1. create/validate the backend virtual environment,
  2. install backend and frontend dependencies when needed,
  3. apply database migrations,
  4. start the FastAPI API and the React UI,
  5. open the dashboard in your browser.

Only the processes started by this launcher are stopped when it exits.
If ATLAS is already running on the default ports, it simply opens the browser.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
LOGS = ROOT / "logs"
IS_WINDOWS = os.name == "nt"
VENV = BACKEND / ".venv"
VENV_PYTHON = VENV / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")
REQUIREMENTS = BACKEND / "requirements.txt"
DEPENDENCY_MARKER = VENV / ".atlas-dependencies"

API_URL = "http://127.0.0.1:8000"
UI_URL = "http://127.0.0.1:5173"
API_PORT = 8000
UI_PORT = 5173

DEMO_EMAIL = "admin@atlas.demo"
DEMO_PASSWORD = "AtlasDemo!2026"

REQUIRED_BACKEND_IMPORTS = (
    "fastapi,uvicorn,sqlalchemy,alembic,jwt,pydantic_settings,httpx,"
    "reportlab,croniter,defusedxml,multipart,email_validator,celery,redis,yaml,pyotp"
)


def say(message: str = "") -> None:
    print(message, flush=True)


def step(message: str) -> None:
    print(f"[ATLAS] {message}", flush=True)


def fail(message: str) -> int:
    print(f"\n[ATLAS] ERROR: {message}\n", flush=True)
    return 1


def http_ok(url: str, needle: bytes | None = None, timeout: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = response.read(4096)
            return response.status == 200 and (needle is None or needle in body)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return False


def api_running() -> bool:
    try:
        with urllib.request.urlopen(f"{API_URL}/health", timeout=1.5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return response.status == 200 and data.get("service") == "atlas-api"
    except Exception:
        return False


def ui_running() -> bool:
    return http_ok(f"{UI_URL}/", needle=b"ATLAS")


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.8)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def read_env_value(key: str) -> str | None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        return None
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.strip() == key:
            return value.strip().strip('"').strip("'")
    return None


def sqlite_database_path() -> Path | None:
    url = read_env_value("ATLAS_DATABASE_URL") or "sqlite:///./atlas.db"
    if not url.startswith("sqlite"):
        return None
    raw = url.split("sqlite:///")[-1]
    path = Path(raw)
    return path if path.is_absolute() else (BACKEND / path).resolve()


def existing_database_state() -> str:
    """Return 'missing', 'empty', 'demo' or 'real' for the local SQLite DB."""
    path = sqlite_database_path()
    if path is None:
        return "real"
    if not path.exists():
        return "missing"
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "users" not in tables or "organizations" not in tables:
                return "empty"
            users = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            demo = connection.execute("SELECT COUNT(*) FROM organizations WHERE slug = 'atlas-demo'").fetchone()[0]
        finally:
            connection.close()
    except sqlite3.Error:
        return "empty"
    if demo:
        return "demo"
    return "real" if users else "empty"


def default_demo_mode() -> bool:
    env = read_env_value("ATLAS_APP_ENV")
    if env in {"production", "test"}:
        return False
    if sqlite_database_path() is None:
        return False
    return existing_database_state() in {"missing", "empty", "demo"}


def run_checked(command: list[str], cwd: Path, description: str) -> bool:
    step(description)
    try:
        result = subprocess.run(command, cwd=str(cwd), check=False)
    except OSError as exc:
        fail(f"{description} failed: {exc}")
        return False
    if result.returncode != 0:
        fail(f"{description} failed (exit code {result.returncode}).")
        return False
    return True


def ensure_env_file() -> None:
    env_file = ROOT / ".env"
    example = ROOT / ".env.example"
    if env_file.exists() or not example.exists():
        return
    shutil.copyfile(example, env_file)
    step("Created .env from .env.example (local development defaults).")


def backend_dependencies_ok() -> bool:
    try:
        result = subprocess.run(
            [str(VENV_PYTHON), "-c", f"import {REQUIRED_BACKEND_IMPORTS}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def local_schema_without_migrations() -> bool:
    """True when a local SQLite DB has tables but no applied Alembic revision,
    which happens when the app created the schema with create_all()."""
    path = sqlite_database_path()
    if path is None or not path.exists():
        return False
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "users" not in tables:
                return False
            if "alembic_version" not in tables:
                return True
            revision = connection.execute("SELECT version_num FROM alembic_version LIMIT 1").fetchone()
            return revision is None
        finally:
            connection.close()
    except sqlite3.Error:
        return False


def ensure_backend(reinstall: bool) -> bool:
    if not VENV_PYTHON.exists():
        step("Creating Python virtual environment (first run)...")
        if not run_checked([sys.executable, "-m", "venv", str(VENV)], ROOT, "Creating backend/.venv"):
            return False

    requirements_time = REQUIREMENTS.stat().st_mtime if REQUIREMENTS.exists() else 0
    marker_time = DEPENDENCY_MARKER.stat().st_mtime if DEPENDENCY_MARKER.exists() else 0

    needs_install = reinstall
    if not needs_install:
        if marker_time and marker_time < requirements_time:
            needs_install = True
        elif not marker_time:
            # Existing environments created by setup.ps1/setup.sh have no marker.
            if backend_dependencies_ok():
                DEPENDENCY_MARKER.touch()
            else:
                needs_install = True

    if needs_install:
        if not run_checked(
            [str(VENV_PYTHON), "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
            BACKEND,
            "Updating pip",
        ):
            return False
        if not run_checked(
            [str(VENV_PYTHON), "-m", "pip", "install", "-r", str(REQUIREMENTS), "--quiet"],
            BACKEND,
            "Installing backend dependencies (first run may take a minute)",
        ):
            return False
        DEPENDENCY_MARKER.touch()

    if local_schema_without_migrations():
        step("Existing local database detected; recording its schema as the migration baseline...")
        if not run_checked(
            [str(VENV_PYTHON), "-m", "alembic", "stamp", "head"],
            BACKEND,
            "Recording database migration baseline",
        ):
            return False

    return run_checked(
        [str(VENV_PYTHON), "-m", "alembic", "upgrade", "head"],
        BACKEND,
        "Applying database migrations",
    )


def frontend_install_needed() -> bool:
    node_modules = FRONTEND / "node_modules"
    if not node_modules.exists():
        return True
    lockfile = FRONTEND / "package-lock.json"
    installed_lock = node_modules / ".package-lock.json"
    if lockfile.exists() and installed_lock.exists():
        return lockfile.stat().st_mtime > installed_lock.stat().st_mtime
    return False


def ensure_frontend(reinstall: bool) -> bool:
    npm = shutil.which("npm")
    node = shutil.which("node")
    if not npm or not node:
        fail(
            "Node.js was not found. Install Node.js 20 or newer from https://nodejs.org "
            "and run this launcher again."
        )
        return False

    vite_entry = FRONTEND / "node_modules" / "vite" / "bin" / "vite.js"
    if reinstall or frontend_install_needed() or not vite_entry.exists():
        step("Installing frontend dependencies (first run may take a minute)...")
        result = subprocess.run(
            f'"{npm}" install --no-audit --no-fund',
            cwd=str(FRONTEND),
            shell=True,
            check=False,
        )
        if result.returncode != 0:
            fail("Frontend dependency installation failed.")
            return False

    if not vite_entry.exists():
        fail("Vite is missing after installation. Delete frontend/node_modules and try again.")
        return False
    return True


def launch(name: str, command: list[str], cwd: Path, env: dict[str, str], log_path: Path) -> tuple[subprocess.Popen | None, object]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(log_path, "w", encoding="utf-8", errors="replace")
    kwargs: dict = {
        "cwd": str(cwd),
        "env": env,
        "stdout": handle,
        "stderr": subprocess.STDOUT,
    }
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(command, **kwargs)
    except OSError as exc:
        handle.close()
        fail(f"Could not start {name}: {exc}")
        return None, handle
    return process, handle


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    if IS_WINDOWS:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def tail(path: Path, lines: int = 25) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def wait_until_ready(
    backend: subprocess.Popen | None,
    frontend: subprocess.Popen | None,
    timeout: int = 120,
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if backend is not None and backend.poll() is not None:
            return False
        if frontend is not None and frontend.poll() is not None:
            return False
        backend_ok = backend is None or api_running()
        frontend_ok = frontend is None or ui_running()
        if backend_ok and frontend_ok:
            return True
        time.sleep(1.5)
    return False


def open_dashboard() -> None:
    try:
        webbrowser.open(UI_URL)
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Start ATLAS with one command.")
    demo_group = parser.add_mutually_exclusive_group()
    demo_group.add_argument("--demo", dest="demo", action="store_true", help="Force demo data and demo accounts.")
    demo_group.add_argument("--no-demo", dest="demo", action="store_false", help="Start without demo data.")
    parser.set_defaults(demo=None)
    parser.add_argument("--no-browser", action="store_true", help="Do not open the dashboard automatically.")
    parser.add_argument("--reinstall", action="store_true", help="Reinstall backend and frontend dependencies.")
    parser.add_argument("--check", action="store_true", help="Start missing services, verify readiness, then stop them.")
    args = parser.parse_args()

    if sys.version_info < (3, 12):
        return fail(f"Python 3.12 or newer is required (found {sys.version.split()[0]}).")

    say("=" * 68)
    say("  ATLAS - Advanced Threat & Asset Lifecycle Security")
    say("  Unified Intelligence. Complete Visibility. Proactive Defence.")
    say("=" * 68)

    # If both parts are already running, do not disturb them.
    api_up = api_running()
    ui_up = ui_running()
    if api_up and ui_up:
        step(f"ATLAS is already running: {UI_URL}")
        step(f"API documentation: {API_URL}/api/docs")
        if not args.no_browser:
            open_dashboard()
        return 0

    # A partially running instance is fine: start only the missing part.
    start_backend = not api_up
    start_frontend = not ui_up

    if start_backend and port_in_use(API_PORT):
        return fail(
            f"Port {API_PORT} is used by another process that is not ATLAS. "
            "Close that program and try again."
        )
    if start_frontend and port_in_use(UI_PORT):
        return fail(
            f"Port {UI_PORT} is used by another process that is not ATLAS. "
            "Close that program and try again."
        )
    if api_up:
        step(f"Using the ATLAS API already running at {API_URL}")
    if ui_up:
        step(f"Using the web interface already running at {UI_URL}")

    demo = default_demo_mode() if args.demo is None else args.demo

    try:
        ensure_env_file()
        if start_backend and not ensure_backend(args.reinstall):
            return 1
        if start_frontend and not ensure_frontend(args.reinstall):
            return 1
    except KeyboardInterrupt:
        return 0

    LOGS.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["ATLAS_APP_ENV"] = "demo" if demo else "development"
    env["ATLAS_SEED_DEMO_DATA"] = "true" if demo else "false"

    backend_process: subprocess.Popen | None = None
    backend_log = None
    frontend_process: subprocess.Popen | None = None
    frontend_log = None

    if start_backend:
        step("Starting the ATLAS API...")
        backend_process, backend_log = launch(
            "ATLAS API",
            [str(VENV_PYTHON), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(API_PORT)],
            BACKEND,
            env,
            LOGS / "backend.log",
        )
        if backend_process is None:
            backend_log.close()
            return 1
    else:
        step("The ATLAS API is already running; leaving it untouched.")

    if start_frontend:
        node = shutil.which("node")
        vite = FRONTEND / "node_modules" / "vite" / "bin" / "vite.js"
        step("Starting the ATLAS web interface...")
        frontend_process, frontend_log = launch(
            "ATLAS web interface",
            [str(node), str(vite), "--host", "127.0.0.1", "--port", str(UI_PORT)],
            FRONTEND,
            os.environ.copy(),
            LOGS / "frontend.log",
        )
        if frontend_process is None:
            if backend_log:
                backend_log.close()
            if frontend_log:
                frontend_log.close()
            stop_process(backend_process)
            return 1
    else:
        step("The web interface is already running; leaving it untouched.")

    step("Waiting for ATLAS to become ready...")
    ready = wait_until_ready(backend_process, frontend_process)

    if not ready:
        say("")
        if backend_process is not None and backend_process.poll() is not None:
            fail("The ATLAS API stopped unexpectedly.")
            say(tail(LOGS / "backend.log"))
        elif frontend_process is not None and frontend_process.poll() is not None:
            fail("The ATLAS web interface stopped unexpectedly.")
            say(tail(LOGS / "frontend.log"))
        else:
            fail("ATLAS did not become ready within 120 seconds.")
            if backend_process is not None:
                say(tail(LOGS / "backend.log"))
            if frontend_process is not None:
                say(tail(LOGS / "frontend.log"))
        stop_process(backend_process)
        stop_process(frontend_process)
        if backend_log:
            backend_log.close()
        if frontend_log:
            frontend_log.close()
        return 1

    say("")
    say("ATLAS is running.")
    say(f"  Dashboard : {UI_URL}")
    say(f"  API docs  : {API_URL}/api/docs")
    if demo:
        say("")
        say("  Demo sign-in:")
        say(f"    Email    : {DEMO_EMAIL}")
        say(f"    Password : {DEMO_PASSWORD}")
        say("    Other demo roles: security@, soc@, vapt@, dev@, exec@atlas.demo")
    else:
        say("  First run: use the workspace bootstrap form on the sign-in page.")
    started_logs = [str(path) for path, handle in ((LOGS / "backend.log", backend_log), (LOGS / "frontend.log", frontend_log)) if handle]
    if started_logs:
        say("")
        say(f"  Logs: {', '.join(started_logs)}")
    say("  Press Ctrl+C to stop the services started by this launcher.")
    say("")

    if not args.no_browser:
        open_dashboard()

    if args.check:
        stop_process(backend_process)
        stop_process(frontend_process)
        if backend_log:
            backend_log.close()
        if frontend_log:
            frontend_log.close()
        say("Readiness check passed; launcher-started services were stopped.")
        return 0

    try:
        while True:
            if backend_process is not None and backend_process.poll() is not None:
                fail("The ATLAS API stopped unexpectedly.")
                say(tail(LOGS / "backend.log"))
                return 1
            if frontend_process is not None and frontend_process.poll() is not None:
                fail("The ATLAS web interface stopped unexpectedly.")
                say(tail(LOGS / "frontend.log"))
                return 1
            time.sleep(1)
    except KeyboardInterrupt:
        say("\nStopping the services started by the ATLAS launcher...")
        return 0
    finally:
        stop_process(backend_process)
        stop_process(frontend_process)
        if backend_log:
            backend_log.close()
        if frontend_log:
            frontend_log.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - launcher must print a readable error
        raise SystemExit(fail(f"Unexpected launcher error: {exc}"))
