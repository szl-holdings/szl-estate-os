"""Shared helpers for the SZL Evidence Explorer operator kit (DRAFT, 2026-10-21).

Standard library only. The Snowflake connector is imported lazily, only by the
operator's own run. Nothing here reads connection parameters from argv, and
nothing here prints connection parameters, error messages from the driver, or
environment values.

Doc basis (fetched 2026-10-21; see SOURCE_VERIFICATION.md):
- connections.toml / default connection / SNOWFLAKE_DEFAULT_CONNECTION_NAME:
  developer-guide/python-connector/python-connector-connect
- SHOW WAREHOUSES column `is_current` ("whether the warehouse is in use for
  the session") and `auto_resume`: sql-reference/sql/show-warehouses
- SHOW RESOURCE MONITORS and SHOW TASKS "don't require a running warehouse":
  sql-reference/sql/show-resource-monitors, show-tasks
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re

KIT_NAME = "szl-ee-operator-kit"
KIT_VERSION = "0.3.0-draft-20261023"

EXIT_OK = 0
EXIT_FAIL = 1          # shutdown verifier: at least one FAIL
EXIT_PARTIAL = 2       # some checks NOT_RUN / UNKNOWN / errored
EXIT_REFUSED = 3       # a safety guard refused
EXIT_CONNECTION = 4    # connector missing or connection failed
EXIT_EXEC_ERROR = 5    # deploy: a statement failed after changes began

CONNECTION_NAME_ENV = "SZL_SF_CONNECTION_NAME"   # optional; else connector default
EXPECTED_ACCOUNT_ENV = "SZL_SF_EXPECTED_ACCOUNT"  # optional; compared, never printed
RUN_ID_ENV = "SZL_EE_RUN_ID"                     # v0.3.0: optional; set by szl_ee_go.py for each run
_RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")   # same format szl_ee_go.py mints

_SECRETISH_ENV = re.compile(r"(PASS|PWD|TOKEN|SECRET|KEY|PRIVATE|CREDENTIAL|AUTH)", re.I)


class RefusedStatement(Exception):
    """Raised before execution when a statement is not permitted."""


class ConnectorUnavailable(Exception):
    pass


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_sql(stmt: str) -> str:
    """Collapse whitespace, strip one trailing semicolon, uppercase.

    Used only for allowlist comparison. Any remaining ';' means multiple
    statements and is refused by callers.
    """
    if not isinstance(stmt, str):
        raise RefusedStatement("statement is not a string")
    s = " ".join(stmt.split())
    if s.endswith(";"):
        s = s[:-1].rstrip()
    return s.upper()


def load_connector():
    """Import snowflake.connector or fail closed."""
    try:
        import snowflake.connector as sc  # type: ignore
    except Exception as exc:  # ImportError or a broken install
        raise ConnectorUnavailable(type(exc).__name__) from None
    return sc


def run_id(env):
    """v0.3.0: the run identifier from SZL_EE_RUN_ID, or None when unset/empty. A set but
    malformed value is refused (fail closed) so it can never inject text into a QUERY_TAG."""
    v = env.get(RUN_ID_ENV)
    if v is None or v == "":
        return None
    if not isinstance(v, str) or not _RUN_ID.fullmatch(v):
        raise RefusedStatement("SZL_EE_RUN_ID malformed")
    return v


def query_tag(base: str, env) -> str:
    """QUERY_TAG for a kit session: '<base>' or '<base>:<run id>' when SZL_EE_RUN_ID is set."""
    rid = run_id(env)
    return base if rid is None else "%s:%s" % (base, rid)


def connect(connector, env, tag: str):
    """Open a connection using ONLY the connector's own config.

    If SZL_SF_CONNECTION_NAME is set, it names a connections.toml entry.
    Otherwise the connector's documented default resolution applies
    ([default] entry, config.toml default_connection_name, or
    SNOWFLAKE_DEFAULT_CONNECTION_NAME). No account/user/password/token is
    passed from this code.
    """
    kwargs = {
        "session_parameters": {
            "QUERY_TAG": query_tag(tag, env),
            "STATEMENT_TIMEOUT_IN_SECONDS": 60,
        },
        "client_session_keep_alive": False,
    }
    name = env.get(CONNECTION_NAME_ENV)
    if name:
        kwargs["connection_name"] = name
    return connector.connect(**kwargs)


def safe_error(exc: BaseException) -> dict:
    """Error summary without the driver's message text (which can echo
    account URLs, user names or SQL)."""
    out = {"error_class": type(exc).__name__}
    for attr in ("errno", "sqlstate"):
        val = getattr(exc, attr, None)
        if isinstance(val, (int, str)) and len(str(val)) <= 16:
            out[attr] = val
    return out


def secret_values(env) -> list:
    vals = []
    for k, v in env.items():
        if _SECRETISH_ENV.search(k) and isinstance(v, str) and len(v) >= 4:
            vals.append(v)
    return vals


def scrub(obj, secrets):
    """Replace any exact or embedded secret value in strings (defence in depth)."""
    if isinstance(obj, str):
        for s in secrets:
            if s and s in obj:
                obj = obj.replace(s, "<scrubbed>")
        return obj
    if isinstance(obj, list):
        return [scrub(x, secrets) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v, secrets) for k, v in obj.items()}
    return obj


def redact_identifier(value) -> str:
    if value is None:
        return None
    return "<redacted:len=%d>" % len(str(value))


def rows_as_dicts(cur) -> list:
    desc = getattr(cur, "description", None) or []
    names = [str(d[0]).lower() for d in desc]
    return [dict(zip(names, row)) for row in (cur.fetchall() or [])]


def keep_columns(rows, allowed) -> list:
    out = []
    for r in rows:
        out.append({k: _jsonable(r.get(k)) for k in allowed if k in r})
    return out


def _jsonable(v):
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat()
    return str(v)


def truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "y", "yes", "1", "on")


def warehouse_gate(wh_rows) -> dict:
    """Decide whether a statement that may need compute can run without
    RESUMING any warehouse.

    Rule (fail-closed):
      - If the session's current warehouse (is_current) is STARTED, a query
        runs on already-running compute: allowed (it may extend idle time).
      - If there is no current warehouse among visible warehouses, a
        compute-needing query errors instead of resuming anything: allowed.
      - Anything else (current warehouse SUSPENDED/RESUMING/unknown state,
        or more than one current row): NOT allowed.
    """
    current = [r for r in wh_rows if truthy(r.get("is_current"))]
    if not current:
        return {"allowed": True, "reason": "no current warehouse in session",
                "current_warehouse_state": None}
    if len(current) > 1:
        return {"allowed": False, "reason": "ambiguous: >1 current warehouse",
                "current_warehouse_state": None}
    state = str(current[0].get("state", "")).upper()
    if state == "STARTED":
        return {"allowed": True, "reason": "current warehouse already STARTED",
                "current_warehouse_state": state}
    return {"allowed": False,
            "reason": "current warehouse is %s; a SELECT could resume it" % (state or "UNKNOWN"),
            "current_warehouse_state": state or "UNKNOWN"}


class GuardedSession:
    """Executes only statements accepted by `check(stmt)`; records query IDs."""

    def __init__(self, conn, check):
        self._conn = conn
        self._check = check
        self.executed = []
        self.refused = []

    def run(self, stmt: str):
        try:
            self._check(stmt)
        except RefusedStatement as exc:
            self.refused.append({"statement_sha256": sha256_text(stmt), "reason": str(exc)})
            raise
        cur = self._conn.cursor()
        cur.execute(stmt)
        qid = getattr(cur, "sfqid", None)
        self.executed.append({"statement": stmt, "query_id": qid if isinstance(qid, str) else None})
        return cur, (qid if isinstance(qid, str) else None)


def allowlist_check(allowed_normalized):
    allowed = frozenset(allowed_normalized)

    def _check(stmt):
        n = normalize_sql(stmt)
        if ";" in n:
            raise RefusedStatement("multiple statements")
        if n not in allowed:
            raise RefusedStatement("statement not on allowlist")
    return _check


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class ProgressFile:
    """v0.3.0: an evidence file that is rewritten after every step so a killed process leaves the
    last complete record. Creation is exclusive (an existing file is never overwritten); each
    write goes to '<path>.tmp', is flushed and fsync'ed, then os.replace()d over '<path>'."""

    def __init__(self, path, env):
        self.path = path
        self.secrets = secret_values(env)
        self.writes = 0
        with open(path, "x", encoding="utf-8", newline="\n") as f:
            f.write("{}\n")
            f.flush()
            os.fsync(f.fileno())

    def write(self, evidence: dict):
        text = json.dumps(scrub(evidence, self.secrets), indent=1, sort_keys=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        self.writes += 1


def emit(evidence: dict, env, out, out_path=None):
    text = json.dumps(scrub(evidence, secret_values(env)), indent=1, sort_keys=True)
    out.write(text + "\n")
    if out_path:
        with open(out_path, "x", encoding="utf-8", newline="\n") as f:  # never overwrite
            f.write(text + "\n")
