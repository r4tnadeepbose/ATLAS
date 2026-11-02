# How to Run It

ATLAS is a web application with two parts: an API (Python/FastAPI) and a user
interface (React). The launcher below starts both, prepares the database, and
opens the dashboard for you.

---

## The easy way (Windows)

1. Open the ATLAS folder.
2. Double-click **`run.bat`**.
3. Wait for the message `ATLAS is running`. The browser opens automatically.
4. Sign in with the demo account (shown below), or use the bootstrap form if
   the instance has no users.

First launch takes longer because Python and Node dependencies are installed and
the database is created. Later launches start in a few seconds.

### Demo sign-in

| Field | Value |
| --- | --- |
| Email | `admin@atlas.demo` |
| Password | `AtlasDemo!2026` |

Other demo roles: `security@`, `soc@`, `vapt@`, `dev@`, `exec@atlas.demo` (same
password). Demo data is synthetic and isolated in a demo organization.

---

## The cross-platform way

```bash
python run.py
```

`run.py` does everything:

- creates `backend/.venv` if missing;
- installs Python and Node dependencies when needed;
- creates `.env` from `.env.example` if missing;
- applies database migrations;
- starts the API on `http://127.0.0.1:8000`;
- starts the UI on `http://127.0.0.1:5173`;
- opens the browser;
- stops only the processes it started when you press `Ctrl+C`.

If ATLAS is already running, it opens the existing dashboard instead of starting
a second copy. If only the API or only the UI is running, it starts the missing
part.

### Launcher options

```bash
python run.py --demo        # force demo data (default on an empty local database)
python run.py --no-demo     # clean instance, use workspace bootstrap
python run.py --no-browser  # do not open the browser
python run.py --reinstall   # reinstall backend + frontend dependencies
python run.py --check       # start missing services, verify readiness, then stop
```

If only one part is running (for example the UI is open but the API was closed),
the launcher starts only the missing part and leaves the other one untouched. If
both are already running, it just opens the dashboard.

---

## What you should see

- **Dashboard:** <http://127.0.0.1:5173>
- **API documentation:** <http://127.0.0.1:8000/api/docs>
- **Health check:** <http://127.0.0.1:8000/health>

Start at **Command Center**. From there you can open Asset Intelligence, the
Microservice Map, SBOM Intelligence, AI Triage, Attack Surface, API Inventory,
Data Classification, Vulnerability Management, Risk Management and Reports.

---

## Dark and light mode

Use the **sun / moon button** in the top bar (also available at the top-right of
the sign-in screen). The choice is saved in the browser and restored on the next
visit. The dark theme is the default.

---

## Stopping ATLAS

Press **`Ctrl+C`** in the launcher window. The launcher stops the API and UI it
started. Closing the window also works, but `Ctrl+C` is the cleanest way.

Logs are written to `logs/backend.log` and `logs/frontend.log` if something fails.

---

## Manual start (if you prefer separate terminals)

**Terminal 1 — API**

```powershell
cd backend
$env:ATLAS_APP_ENV="demo"
$env:ATLAS_SEED_DEMO_DATA="true"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

**Terminal 2 — UI**

```powershell
cd frontend
npm run dev
```

On Linux/macOS use `./.venv/bin/python` instead of `.\.venv\Scripts\python.exe`.

First-time manual setup:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

---

## Docker alternative

```bash
cp .env.example .env
# edit ATLAS_SECRET_KEY and passwords in .env
docker compose up --build
```

- UI: <http://localhost:8080>
- API docs: <http://localhost:8000/api/docs>

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `Python was not found` | Install Python 3.12+ from <https://www.python.org/downloads/> and tick “Add Python to PATH”. |
| `Node.js was not found` | Install Node.js 20+ from <https://nodejs.org>. |
| Port 8000 or 5173 already in use | Close the other ATLAS window/process, or stop the program using that port. |
| Browser does not open | Open <http://127.0.0.1:5173> manually. |
| Login says account deactivated | An administrator disabled that account in User Management; re-enable it there. |
| Dependencies look broken | Run `python run.py --reinstall`. |
| Want a clean demo again | Stop ATLAS, delete `backend/atlas.db`, start again. This deletes local data. |
| API starts but UI fails | Check `logs/frontend.log`; usually `npm install` failed. |

---

## Requirements

- Windows 10/11, Linux or macOS
- Python 3.12 or newer
- Node.js 20 or newer
- No database server required for local use (SQLite is the default)
- Optional: Docker Desktop for the containerized stack

For a short explanation of what ATLAS is and how information flows through it,
read [HOW_IT_WORKS.md](HOW_IT_WORKS.md).
