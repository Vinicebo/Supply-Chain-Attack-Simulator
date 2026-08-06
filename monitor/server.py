"""
Monitoring dashboard for the Supply Chain Attack Simulator.

This FastAPI server plays the role of the attacker's collection server -- BUT
runs on loopback and only records what the demo payload sends. It:

  * exposes POST /beacon to receive metadata from the post-install hook,
  * stores every capture in a SQLite database,
  * renders a dashboard (GET /) of captured hosts and metadata, and
  * renders a timeline (GET /timeline) of the install -> collection sequence.

Run:  uv run uvicorn monitor.server:app --port 8090
   or python runner/demo.py monitor
"""
from __future__ import annotations

import html
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

# Make the repo root importable whether launched as module or script.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scas_config as cfg  # noqa: E402

DB_PATH = cfg.MONITOR_DB


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS captures (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at    TEXT NOT NULL,
                remote_addr    TEXT,
                trigger        TEXT,
                package        TEXT,
                package_version TEXT,
                hostname       TEXT,
                username       TEXT,
                python_version TEXT,
                platform       TEXT,
                cwd            TEXT,
                pid            INTEGER,
                collected_at   TEXT,
                raw_json       TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                at          TEXT NOT NULL,
                kind        TEXT NOT NULL,
                detail      TEXT
            )
            """
        )
        conn.commit()


def record_event(kind: str, detail: str = "") -> None:
    """Timeline hook other components can call to log demo milestones."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO events (at, kind, detail) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), kind, detail),
        )
        conn.commit()


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI(title="SCAS Monitor", version="1.0.0")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    record_event("monitor_started", "Monitor came online and is listening for beacons.")


@app.post(cfg.MONITOR_BEACON_PATH)
async def beacon(request: Request) -> JSONResponse:
    """Receive the exfiltration beacon from the post-install hook."""
    try:
        payload = await request.json()
    except Exception:
        payload = {"error": "unparseable body", "raw": (await request.body()).decode("utf-8", "replace")}

    now = datetime.now(timezone.utc).isoformat()
    remote = request.client.host if request.client else "unknown"

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO captures (
                received_at, remote_addr, trigger, package, package_version,
                hostname, username, python_version, platform, cwd, pid,
                collected_at, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now, remote,
                payload.get("trigger"), payload.get("package"),
                payload.get("package_version"), payload.get("hostname"),
                payload.get("username"), payload.get("python_version"),
                payload.get("platform"), payload.get("cwd"), payload.get("pid"),
                payload.get("collected_at"), json.dumps(payload),
            ),
        )
        conn.commit()

    record_event(
        "beacon_received",
        f"Captured {payload.get('package')}=={payload.get('package_version')} "
        f"from {payload.get('hostname')} ({payload.get('username')})",
    )
    return JSONResponse({"status": "captured", "received_at": now})


@app.get("/api/captures")
def api_captures() -> JSONResponse:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM captures ORDER BY id DESC").fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM captures ORDER BY id DESC").fetchall()
    return HTMLResponse(_render_dashboard(rows))


@app.get("/timeline", response_class=HTMLResponse)
def timeline() -> HTMLResponse:
    with _connect() as conn:
        events = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    return HTMLResponse(_render_timeline(events))


# --------------------------------------------------------------------------- #
# Rendering (no template engine -- keep deps minimal)
# --------------------------------------------------------------------------- #
_STYLE = """
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 0; background: #0d1117; color: #c9d1d9; }
  header { background: #161b22; padding: 18px 28px; border-bottom: 1px solid #30363d; }
  h1 { margin: 0; font-size: 20px; color: #f0f6fc; }
  .sub { color: #8b949e; font-size: 13px; margin-top: 4px; }
  nav a { color: #58a6ff; margin-right: 18px; text-decoration: none; font-size: 14px; }
  main { padding: 24px 28px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
          padding: 16px 18px; margin-bottom: 16px; }
  .flag { color: #ff7b72; font-weight: bold; }
  .k { color: #8b949e; }
  .v { color: #e6edf3; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 4px 10px 4px 0; vertical-align: top; font-size: 13px; }
  .empty { color: #8b949e; padding: 40px; text-align: center; }
  .badge { background: #ff7b72; color: #0d1117; border-radius: 4px;
           padding: 1px 6px; font-size: 11px; font-weight: bold; }
  .pkglist { color: #8b949e; font-size: 12px; word-break: break-word; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%;
         margin-right:8px; }
  .ev { border-left: 2px solid #30363d; padding: 6px 0 6px 16px; margin-left: 5px; }
  .ev .t { color:#8b949e; font-size:12px; }
</style>
"""


def _shell(title: str, body: str) -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{html.escape(title)}</title>{_STYLE}</head><body>
<header>
  <h1>🛰️ SCAS Monitor <span class="badge">SIMULATION</span></h1>
  <div class="sub">Loopback collection server &mdash; captures the post-install beacon</div>
  <nav style="margin-top:10px">
    <a href="/">Captures</a><a href="/timeline">Timeline</a><a href="/api/captures">JSON</a>
  </nav>
</header><main>{body}</main></body></html>"""


def _render_dashboard(rows) -> str:
    if not rows:
        body = ('<div class="card empty">No beacons captured yet.<br>'
                'Run the demo to install <code>internal-auth-utils</code> and '
                'watch it phone home.</div>')
        return _shell("SCAS Monitor", body)

    cards = []
    for r in rows:
        try:
            raw = json.loads(r["raw_json"])
        except Exception:
            raw = {}
        pkgs = raw.get("installed_packages_sample", [])
        compromised = (r["package_version"] == "99.0.0")
        flag = ('<span class="flag">⚠ MALICIOUS VERSION 99.0.0 INSTALLED</span>'
                if compromised else "")
        cards.append(f"""
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div><span class="dot" style="background:{'#ff7b72' if compromised else '#3fb950'}"></span>
              <b class="v">{html.escape(str(r['package']))}=={html.escape(str(r['package_version']))}</b></div>
            <div class="k">{html.escape(str(r['received_at']))}</div>
          </div>
          {flag}
          <table>
            <tr><td class="k">host</td><td class="v">{html.escape(str(r['hostname']))}</td></tr>
            <tr><td class="k">user</td><td class="v">{html.escape(str(r['username']))}</td></tr>
            <tr><td class="k">python</td><td class="v">{html.escape(str(r['python_version']))}</td></tr>
            <tr><td class="k">platform</td><td class="v">{html.escape(str(r['platform']))}</td></tr>
            <tr><td class="k">cwd</td><td class="v">{html.escape(str(r['cwd']))}</td></tr>
            <tr><td class="k">trigger</td><td class="v">{html.escape(str(r['trigger']))} (pid {html.escape(str(r['pid']))})</td></tr>
            <tr><td class="k">source ip</td><td class="v">{html.escape(str(r['remote_addr']))}</td></tr>
            <tr><td class="k">pkgs seen</td><td class="pkglist">{html.escape(', '.join(map(str, pkgs)))}</td></tr>
          </table>
        </div>""")
    header = f'<div class="card">Captured <b>{len(rows)}</b> beacon(s). Each row is proof that installing a package executed attacker code.</div>'
    return _shell("SCAS Monitor", header + "".join(cards))


def _render_timeline(events) -> str:
    if not events:
        return _shell("Timeline", '<div class="card empty">No events recorded yet.</div>')
    items = []
    for e in events:
        items.append(
            f'<div class="ev"><div class="t">{html.escape(str(e["at"]))} '
            f'&middot; <b>{html.escape(str(e["kind"]))}</b></div>'
            f'<div class="v">{html.escape(str(e["detail"]))}</div></div>'
        )
    return _shell("Timeline", '<div class="card">'
                  '<h3 style="margin-top:0">Attack timeline</h3>'
                  + "".join(items) + "</div>")


if __name__ == "__main__":
    import uvicorn

    init_db()
    uvicorn.run(app, host=cfg.MONITOR_HOST, port=cfg.MONITOR_PORT)
