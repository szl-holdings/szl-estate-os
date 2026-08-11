#!/usr/bin/env python3
"""Operational local runtime for Estate OS Action Assurance.

Commands:
  ingest  Validate fixture/producer passports and persist immutable records.
  status  Print durable store status.
  report  Print current modeled Trust Factor and citation state.
  serve   Run a read-only local dashboard/API.

This runtime performs no external mutations and has no write HTTP endpoints.
A non-loopback bind requires --allow-remote plus SZL_ACTION_CONTROL_TOKEN.
"""

from __future__ import annotations

import argparse
import hmac
import http.server
import json
import os
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from estate.action_assurance import load_json_documents, parse_timestamp  # noqa: E402
from estate.action_assurance_contract import reject_non_finite_json_constant  # noqa: E402
from estate.action_assurance_store import (  # noqa: E402
    current_trust_report,
    ingest_action_assurance,
    latest_citation_report,
    list_passports,
    store_status,
)

DEFAULT_DB = ROOT / "outputs" / "estate.db"
DEFAULT_PASSPORTS = ROOT / "fixtures" / "action_assurance" / "passports"
DEFAULT_CITATIONS = ROOT / "fixtures" / "action_assurance" / "citations.current.json"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788
MAX_BODY = 2_000_000


def _json(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_non_finite_json_constant,
    )
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _parse_now(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError("--now must be a timezone-aware ISO-8601 timestamp")
    return parsed


def _loopback(host: str) -> bool:
    normalized = host.strip().lower()
    return normalized in {"127.0.0.1", "localhost", "::1"}


def _control_token() -> str | None:
    value = os.environ.get("SZL_ACTION_CONTROL_TOKEN")
    return value.strip() if value and value.strip() else None


def _authorized(header: str | None, token: str | None) -> bool:
    if token is None:
        return True
    prefix = "Bearer "
    if not isinstance(header, str) or not header.startswith(prefix):
        return False
    return hmac.compare_digest(header[len(prefix) :], token)


def _dashboard(status: dict[str, Any]) -> bytes:
    latest = status.get("latest_ingest") or {}
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Action Assurance Runtime</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:980px;margin:40px auto;padding:0 20px;line-height:1.5}}
code{{background:#f2f2f2;padding:.15rem .35rem;border-radius:.3rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
.card{{border:1px solid #ddd;border-radius:10px;padding:16px}}
.small{{color:#555;font-size:.92rem}}
</style>
</head>
<body>
<h1>Action Assurance Runtime</h1>
<p>Read-only local surface for persisted Counterfactual Action Passports.</p>
<div class="grid">
<div class="card"><strong>{status['passport_count']}</strong><br>passports</div>
<div class="card"><strong>{status['agent_count']}</strong><br>agents</div>
<div class="card"><strong>{status['unsigned_count']}</strong><br>unsigned</div>
<div class="card"><strong>{status['signed_unverified_count']}</strong><br>signed / unverified</div>
</div>
<h2>Latest ingest</h2>
<pre>{json.dumps(latest, indent=2, sort_keys=True)}</pre>
<h2>API</h2>
<ul>
<li><code>/healthz</code></li>
<li><code>/readyz</code></li>
<li><code>/api/v1/action-assurance/status</code></li>
<li><code>/api/v1/action-assurance/passports</code></li>
<li><code>/api/v1/action-assurance/trust-factors</code></li>
<li><code>/api/v1/action-assurance/citations</code></li>
</ul>
<p class="small">No write HTTP endpoint exists. External actions, signing, key custody, and deployment remain outside this process.</p>
</body></html>"""
    return body.encode("utf-8")


class ActionAssuranceHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SZLActionAssurance/1"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, value: Any) -> None:
        self._send(status, _json(value), "application/json; charset=utf-8")

    def _deny_if_needed(self) -> bool:
        token = getattr(self.server, "control_token", None)
        if _authorized(self.headers.get("Authorization"), token):
            return False
        self._send_json(401, {"error": "unauthorized"})
        return True

    def do_POST(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "read_only_runtime"})

    def do_PUT(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "read_only_runtime"})

    def do_PATCH(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "read_only_runtime"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "read_only_runtime"})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if self._deny_if_needed():
            return
        db_path: Path = getattr(self.server, "db_path")
        if parsed.path == "/readyz":
            status = store_status(db_path)
            ready = status["latest_ingest"] is not None
            self._send_json(200 if ready else 503, {"ready": ready, "status": status})
            return
        if parsed.path == "/":
            self._send(200, _dashboard(store_status(db_path)), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/v1/action-assurance/status":
            self._send_json(200, store_status(db_path))
            return
        if parsed.path == "/api/v1/action-assurance/passports":
            query = urllib.parse.parse_qs(parsed.query)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except ValueError:
                self._send_json(400, {"error": "invalid_limit"})
                return
            items = list_passports(
                db_path,
                limit=limit,
                agent_id=query.get("agent_id", [None])[0],
                decision=query.get("decision", [None])[0],
            )
            self._send_json(200, {"count": len(items), "items": items})
            return
        if parsed.path == "/api/v1/action-assurance/trust-factors":
            self._send_json(200, current_trust_report(db_path))
            return
        if parsed.path == "/api/v1/action-assurance/citations":
            value = latest_citation_report(db_path)
            self._send_json(200 if value is not None else 404, value or {"error": "unavailable"})
            return
        self._send_json(404, {"error": "not_found"})

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("action-assurance " + (format % args) + "\n")


class ActionAssuranceServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True

    def __init__(self, address: tuple[str, int], db_path: Path, control_token: str | None):
        super().__init__(address, ActionAssuranceHandler)
        self.db_path = db_path
        self.control_token = control_token


def command_ingest(args: argparse.Namespace) -> int:
    passports, load_errors = load_json_documents(args.passports)
    if load_errors:
        print(json.dumps({"status": "FAIL", "load_errors": load_errors}, indent=2))
        return 1
    try:
        citations = _read_object(args.citations)
        now = _parse_now(args.now)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    result = ingest_action_assurance(
        args.database,
        passports,
        citations,
        source_label=args.source_label,
        now=now,
    )
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return 0 if result["status"] == "PASS" else 1


def command_status(args: argparse.Namespace) -> int:
    print(json.dumps(store_status(args.database), indent=2, sort_keys=True))
    return 0


def command_report(args: argparse.Namespace) -> int:
    report = {
        "status": store_status(args.database),
        "trust_factors": current_trust_report(args.database),
        "citations": latest_citation_report(args.database),
    }
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return 0


def command_serve(args: argparse.Namespace) -> int:
    token = _control_token()
    if not _loopback(args.host):
        if not args.allow_remote:
            print("ERROR: non-loopback bind requires --allow-remote", file=sys.stderr)
            return 2
        if token is None:
            print("ERROR: non-loopback bind requires SZL_ACTION_CONTROL_TOKEN", file=sys.stderr)
            return 2
    server = ActionAssuranceServer((args.host, args.port), args.database, token if not _loopback(args.host) else None)
    print(f"Action Assurance runtime: http://{args.host}:{args.port}")
    print(f"Database: {args.database}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--database", type=Path, default=DEFAULT_DB)
    sub = root.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="validate and persist passports")
    ingest.add_argument("--passports", type=Path, default=DEFAULT_PASSPORTS)
    ingest.add_argument("--citations", type=Path, default=DEFAULT_CITATIONS)
    ingest.add_argument("--source-label", default="local")
    ingest.add_argument("--now")
    ingest.set_defaults(func=command_ingest)

    status = sub.add_parser("status", help="show durable store status")
    status.set_defaults(func=command_status)

    report = sub.add_parser("report", help="show trust and citation reports")
    report.set_defaults(func=command_report)

    serve = sub.add_parser("serve", help="serve read-only dashboard/API")
    serve.add_argument("--host", default=DEFAULT_HOST)
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--allow-remote", action="store_true")
    serve.set_defaults(func=command_serve)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
