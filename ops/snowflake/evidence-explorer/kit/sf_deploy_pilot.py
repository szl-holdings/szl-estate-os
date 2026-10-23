#!/usr/bin/env python3
"""Deploy the SZL Evidence Explorer private pilot (DRAFT 2026-10-21; guard hardened v0.1.2 2026-10-22).

v0.3.0 (DRAFT 2026-10-23, narrow design): the owner creates SZL_EE_RM, SZL_EE_WH and the six
SZL_EE_* roles (decision D0). The kit never creates roles or warehouses; it REQUIRES them to exist
with exact properties, runs only as SZL_EE_SETUP / SZL_EE_OWNER / SZL_EE_APP, refuses if the
connected identity can reach any admin or runtime role, tags sessions with SZL_EE_RUN_ID, and
rewrites --out after every statement (fsync) so a killed deploy leaves a record.

v0.1.2: deploy_check now (a) refuses comments, double-quoted identifiers,
backslashes, $$ blocks, unbalanced quotes and non-ASCII outside string
literals before normalising, (b) accepts a GRANT only if it is one cell of an
exact privilege matrix (GRANT_MATRIX) or one of the documented role-hierarchy
grants (ROLE_GRANTS), and (c) requires kit-generated CREATE WAREHOUSE / STAGE /
STREAMLIT / PUT statements to equal the kit's own text. See
PRIVILEGE_OBJECT_DIFF.md. NOT APPROVED FOR LIVE USE.

DEFAULT IS --dry-run: prints the exact ordered statements of DEPLOYMENT_PLAN.md
and executes nothing (the connector is not even imported).

Real execution requires ALL of:
  --execute
  --approval-file F   whose single line matches APPROVAL_TEMPLATE exactly,
                      with 1 <= N <= CAP_CREDITS and a future UTC date
  --manifest M.json   pinning sha256 of schema.sql, reader_grants.sql and
                      streamlit_app.py (+ evidence_core.py if the app imports it;
                      produced by the SQL/app track)
  the approval's account == CURRENT_ACCOUNT() or ORG-ACCOUNT_NAME at runtime
  resource monitor SZL_EE_RM already created MANUALLY by the owner as
  ACCOUNTADMIN, with CREDIT_QUOTA == N and FREQUENCY NEVER
  v0.3.0: warehouse SZL_EE_WH and the six roles already created by the owner (D0)
  with the exact properties in EXPECTED_WAREHOUSE; database SZL_EE_DB does not exist
  v0.3.0: the identity's CURRENT_AVAILABLE_ROLES() contains SZL_EE_SETUP and no admin or
  runtime role

It never executes ACCOUNTADMIN, DROP, REPLACE, IF NOT EXISTS, RESUME, DML,
integrations, secrets, users, tasks or network objects. Exit codes:
0 ok, 3 refused, 4 connector/connection failure, 5 a statement failed after
changes began (partial state is reported; nothing is rolled back or dropped).
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sf_kit_common as K  # noqa: E402

CAP_CREDITS = 10            # kit ceiling (COST_AND_SHUTDOWN.md proposal); approval N must be <= this
MAX_WINDOW_DAYS = 31
APPROVAL_TEMPLATE = ("I approve SZL Evidence Explorer pilot 1: max <N> credits, warehouse XS, "
                     "auto_suspend 60, until <UTC date>, account <locator>")
_APPROVAL_RE = re.compile(
    r"I approve SZL Evidence Explorer pilot 1: max (?P<n>[1-9][0-9]{0,3}) credits, warehouse XS, "
    r"auto_suspend 60, until (?P<d>[0-9]{4}-[0-9]{2}-[0-9]{2}), account (?P<a>[A-Za-z0-9][A-Za-z0-9_-]{1,63})")
REQUIRED_FILES = ("schema.sql", "reader_grants.sql", "streamlit_app.py")
OPTIONAL_APP_FILES = ("evidence_core.py",)       # staged next to streamlit_app.py when pinned
GUARD_LINE = "<<DEPLOYMENT_APPROVAL_REF_REQUIRED>>"   # SQL/app track's fail-closed first line
_GUARD_REF = re.compile(r"-- DEPLOYMENT_APPROVAL_REF: (?P<h>[0-9a-f]{64})")

# Object names follow the SQL/app track bundle (schema.sql / reader_grants.sql), not the v1 plan.
DB, DATA_SCHEMA, APP_SCHEMA = "SZL_EE_DB", "SZL_EE_DB.EE_DATA", "SZL_EE_DB.EE_APP"
WH, RM = "SZL_EE_WH", "SZL_EE_RM"
STAGE, APP = "SZL_EE_DB.EE_APP.APP_SRC", "SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER"
# v0.3.0: all six roles are created by the owner in D0; the kit only checks that they exist.
ROLES = ("SZL_EE_SETUP", "SZL_EE_OWNER", "SZL_EE_INGEST", "SZL_EE_APP", "SZL_EE_VIEWER", "SZL_EE_OPERATOR")
SETUP_ROLE = "SZL_EE_SETUP"
ROLE_COMMENTS = {
    "SZL_EE_SETUP": "Deploy-time only: CREATE DATABASE ON ACCOUNT. Revoke after deploy.",
    "SZL_EE_OWNER": "Owns EE schemas and tables. Not used by the app or loader.",
    "SZL_EE_INGEST": "Loader: SELECT and INSERT only on EE_DATA tables.",
    "SZL_EE_APP": "Owns the Streamlit object; owner-rights queries are SELECT-only.",
    "SZL_EE_VIEWER": "View-only audience: USAGE on db, app schema and app object only.",
    "SZL_EE_OPERATOR": "Runtime warehouse control: OPERATE on SZL_EE_WH only (resume/suspend).",
}
# Roles the deploy identity must NOT be able to reach (directly or through the hierarchy).
ADMIN_ROLES = frozenset({"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN", "ORGADMIN", "GLOBALORGADMIN"})
NOT_FOR_SETUP = frozenset({"SZL_EE_INGEST", "SZL_EE_OPERATOR", "SZL_EE_VIEWER"})
CONTEXT_SQL = ("SELECT CURRENT_ACCOUNT(), CURRENT_ORGANIZATION_NAME(), CURRENT_ACCOUNT_NAME(), "
               "CURRENT_AVAILABLE_ROLES()")
SHOW_PARAMS_SQL = "SHOW PARAMETERS LIKE 'STATEMENT%' IN WAREHOUSE SZL_EE_WH"
EXPECTED_WH_PARAMS = {"STATEMENT_TIMEOUT_IN_SECONDS": "120", "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS": "60"}
OWNERSHIP_SQL = frozenset({"GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_OWNER REVOKE CURRENT GRANTS",
                           "GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_OWNER"})

_DENY = [re.compile(p) for p in (
    r"\bDROP\b", r"\bREPLACE\b", r"\bTRUNCATE\b", r"\bDELETE\b", r"\bUNDROP\b", r"\bACCOUNTADMIN\b",
    r"\bRESUME\b", r"\bALTER\s+(ACCOUNT|WAREHOUSE|USER|DATABASE|SCHEMA|STREAMLIT|STAGE)\b",
    r"\bOR\s+ALTER\b", r"\bPUBLIC\b", r"\bFUTURE\b", r"\bWITH\s+GRANT\s+OPTION\b",
    r"\bIF\s+NOT\s+EXISTS\b", r"\bCREATE\s+USER\b", r"\bTO\s+USER\b", r"\bSECRETS?\b",
    r"\bINTEGRATIONS?\b", r"\bNETWORK\s+(POLICY|RULE)\b", r"\bTASKS?\b", r"\bCOMPUTE\s+POOL\b",
    r"\bPIPE\b", r"\bAUTO_RESUME\s*=\s*TRUE\b", r"\b(UPDATE|MERGE|COPY|CALL|EXECUTE)\b",
    r"\bMANAGE\s+GRANTS\b", r"\bRESOURCE\s+MONITORS?\b", r"\bSHARES?\b", r"\bON\s+ACCOUNT\b",
    r"\bCLONE\b", r"\bEMBED\b", r"\bERROR_LOGGING\b",
)]
# v0.1.2 exact privilege matrix: (object type, object) -> {grantee role: allowed privileges}.
# v0.3.0: these are the ONLY grants the kit may execute. Warehouse grants (USAGE for APP/INGEST,
# OPERATE for SZL_EE_OPERATOR) are owner-run in D0 and listed in OWNER_RUN_GRANTS; the kit refuses them.
# A privilege GRANT is accepted only if its target cell exists and its privileges are a subset
# of the cell. Anything else (ALL, ON ALL/FUTURE, ON ACCOUNT, OPERATE/MODIFY/MONITOR, other
# databases/warehouses, VIEWER data access, TO SHARE/DATABASE ROLE/APPLICATION) is refused.
PILOT_TABLES = ("ASSETS", "REVISIONS", "OBSERVATIONS", "RIGHTS_RECORDS", "INGESTION_BATCHES",
                "EXCLUSIONS", "REJECTED_ROWS")
GRANT_MATRIX = {
    ("DATABASE", "SZL_EE_DB"): {"SZL_EE_INGEST": {"USAGE"}, "SZL_EE_APP": {"USAGE"}, "SZL_EE_VIEWER": {"USAGE"}},
    ("SCHEMA", "SZL_EE_DB.EE_DATA"): {"SZL_EE_INGEST": {"USAGE"}, "SZL_EE_APP": {"USAGE"}},
    ("SCHEMA", "SZL_EE_DB.EE_APP"): {"SZL_EE_APP": {"USAGE", "CREATE STREAMLIT"}, "SZL_EE_VIEWER": {"USAGE"}},
    ("STAGE", "SZL_EE_DB.EE_APP.APP_SRC"): {"SZL_EE_APP": {"READ"}},
    ("STREAMLIT", "SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER"): {"SZL_EE_VIEWER": {"USAGE"}},
}
for _t in PILOT_TABLES:
    GRANT_MATRIX[("TABLE", "SZL_EE_DB.EE_DATA." + _t)] = {"SZL_EE_INGEST": {"SELECT", "INSERT"},
                                                         "SZL_EE_APP": {"SELECT"}}
del _t
# Role-to-role grants the kit may execute: none (v0.3.0). The three v3 '... TO ROLE SYSADMIN'
# hierarchy grants are removed; SZL_EE_OWNER / SZL_EE_APP reach the deploy identity through
# SZL_EE_SETUP, granted by the owner (D3).
ROLE_GRANTS = frozenset()
# Owner-run grants (SNOWSIGHT_SETUP.sql). Documentation and dry-run output only; never executed by
# the kit. (decision, executor role, statement)
OWNER_RUN_GRANTS = (
    ("D0", "ACCOUNTADMIN", "GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_APP"),
    ("D0", "ACCOUNTADMIN", "GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_INGEST"),
    ("D0", "ACCOUNTADMIN", "GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_OPERATOR"),
    # read-only monitor visibility for the runtime's PRIMARY role, so sf_shutdown_verify (own session,
    # DEFAULT_SECONDARY_ROLES = ()) can read SZL_EE_RM without activating SZL_EE_OPERATOR
    ("D0", "ACCOUNTADMIN", "GRANT MONITOR ON RESOURCE MONITOR SZL_EE_RM TO ROLE SZL_EE_INGEST"),
    ("D3", "SECURITYADMIN", "GRANT CREATE DATABASE ON ACCOUNT TO ROLE SZL_EE_SETUP"),
    ("D3", "ACCOUNTADMIN", "GRANT MONITOR ON RESOURCE MONITOR SZL_EE_RM TO ROLE SZL_EE_SETUP"),
    ("D3", "USERADMIN", "GRANT ROLE SZL_EE_OWNER TO ROLE SZL_EE_SETUP"),
    ("D3", "USERADMIN", "GRANT ROLE SZL_EE_APP TO ROLE SZL_EE_SETUP"),
    ("D3", "USERADMIN", "GRANT ROLE SZL_EE_SETUP TO USER SZL_EE_DEPLOY"),
    ("D4", "USERADMIN", "GRANT ROLE SZL_EE_INGEST TO USER SZL_EE_RUNTIME"),
    ("D4b", "USERADMIN", "GRANT ROLE SZL_EE_OPERATOR TO USER SZL_EE_RUNTIME"),
)
_IDENT = r"[A-Z_][A-Z0-9_]*"
_PRIV = r"[A-Z]+(?: [A-Z]+)?"
_PRIV_GRANT = re.compile(r"GRANT (?P<privs>" + _PRIV + r"(?:, " + _PRIV + r")*) ON "
                         r"(?P<otype>DATABASE|SCHEMA|TABLE|WAREHOUSE|STAGE|STREAMLIT) "
                         r"(?P<obj>" + _IDENT + r"(?:\." + _IDENT + r"){0,2}) TO ROLE (?P<role>" + _IDENT + r")")
_ROLE_GRANT = re.compile(r"GRANT ROLE (?P<granted>" + _IDENT + r") TO ROLE (?P<role>" + _IDENT + r")")
_RAW_OK = re.compile(r"[\x20-\x7e\t\r\n]*")
_TABLE_DENY = re.compile(r"\bCLUSTER\s+BY\b|\bCHANGE_TRACKING\b|\bPOLICY\b|\bWITH\s+TAG\b|\bTAG\s*\(|"
                         r"\bMAX_DATA_EXTENSION_TIME_IN_DAYS\b|\bENABLE_SCHEMA_EVOLUTION\b")
_ALLOWED_PREFIX = re.compile(
    r"^(USE SECONDARY ROLES NONE$|USE ROLE (SZL_EE_SETUP|SZL_EE_OWNER|SZL_EE_APP)$|"
    r"SHOW (WAREHOUSES|DATABASES|RESOURCE MONITORS|ROLES) LIKE '[A-Z_%]+'$|SHOW WAREHOUSES$|"
    r"SHOW PARAMETERS LIKE 'STATEMENT%' IN WAREHOUSE SZL_EE_WH$|GRANT |"
    r"CREATE DATABASE SZL_EE_DB |CREATE SCHEMA SZL_EE_DB\.EE_(DATA|APP) WITH MANAGED ACCESS( |$)|"
    r"CREATE TABLE |"
    r"CREATE STAGE SZL_EE_DB\.EE_APP\.APP_SRC |PUT 'FILE://|"
    r"CREATE STREAMLIT SZL_EE_DB\.EE_APP\.SZL_EVIDENCE_EXPLORER )")
_FILE_PREFIX = {
    "schema.sql": re.compile(r"^(USE ROLE (SZL_EE_SETUP|SZL_EE_OWNER)$|GRANT |CREATE DATABASE |"
                             r"CREATE SCHEMA |CREATE TABLE )"),
    "reader_grants.sql": re.compile(r"^(USE ROLE SZL_EE_OWNER$|GRANT )"),
}


# v0.3.0: owner-run in D0 (never executed by the kit); the preflight checks the live warehouse
# against EXPECTED_WAREHOUSE, which mirrors this statement.
WAREHOUSE_SQL = ("CREATE WAREHOUSE %s WITH WAREHOUSE_SIZE = XSMALL MAX_CLUSTER_COUNT = 1 MIN_CLUSTER_COUNT = 1 "
                 "AUTO_SUSPEND = 60 AUTO_RESUME = FALSE INITIALLY_SUSPENDED = TRUE RESOURCE_MONITOR = %s "
                 "STATEMENT_TIMEOUT_IN_SECONDS = 120 STATEMENT_QUEUED_TIMEOUT_IN_SECONDS = 60 "
                 "COMMENT = 'SZL synthetic pilot 1'") % (WH, RM)
STAGE_SQL = "CREATE STAGE %s DIRECTORY = (ENABLE = TRUE) COMMENT = 'app source'" % STAGE
STREAMLIT_SQL = ("CREATE STREAMLIT %s FROM '@%s/v1' MAIN_FILE = 'streamlit_app.py' QUERY_WAREHOUSE = %s "
                 "TITLE = 'SZL Evidence Explorer - SYNTHETIC DATA' COMMENT = 'private synthetic pilot 1'") % (APP, STAGE, WH)
EXPECTED_WAREHOUSE = {"state": "SUSPENDED", "size": "XSMALL", "auto_resume": "false", "auto_suspend": "60",
                      "resource_monitor": RM, "owner": "ACCOUNTADMIN", "type": "STANDARD"}
_PUT_RX = re.compile(r"PUT 'FILE://[^']+' @SZL_EE_DB\.EE_APP\.APP_SRC/V1 AUTO_COMPRESS = FALSE OVERWRITE = FALSE")


def _lexical_check(stmt: str):
    """v0.1.2: refuse text whose lexing could differ between this guard and Snowflake.
    Runs on the RAW statement, before normalize_sql (whose str.split() would turn
    NBSP and other Unicode spaces into ASCII spaces)."""
    if not isinstance(stmt, str):
        raise K.RefusedStatement("statement is not a string")
    if "\\" in stmt:
        raise K.RefusedStatement("backslash not permitted (string-escape lexing differs)")
    if "$$" in stmt:
        raise K.RefusedStatement("dollar-quoted text not permitted")
    outside = _strip_literals(stmt)
    if "'" in outside.replace("''", ""):
        raise K.RefusedStatement("unbalanced string literal")
    if not _RAW_OK.fullmatch(outside):
        raise K.RefusedStatement("non-ASCII or control character outside string literals")
    if "--" in outside or "/*" in outside or "*/" in outside or "//" in outside:
        raise K.RefusedStatement("comment inside statement")
    if '"' in outside or "`" in outside:
        raise K.RefusedStatement("quoted identifiers not permitted")


def _grant_check(n: str, bare: str):
    if n in OWNERSHIP_SQL:
        return
    g = re.sub(r"\s*,\s*", ", ", bare)
    m = _ROLE_GRANT.fullmatch(g)
    if m:
        if (m.group("granted"), m.group("role")) not in ROLE_GRANTS:
            raise K.RefusedStatement("role grant not permitted")
        return
    m = _PRIV_GRANT.fullmatch(g)
    if not m:
        raise K.RefusedStatement("malformed or unsupported GRANT form")
    cell = GRANT_MATRIX.get((m.group("otype"), m.group("obj")), {}).get(m.group("role"))
    if cell is None:
        raise K.RefusedStatement("grant target not in privilege matrix")
    privs = m.group("privs").split(", ")
    if len(set(privs)) != len(privs):
        raise K.RefusedStatement("duplicate privilege in GRANT")
    if not set(privs) <= cell:
        raise K.RefusedStatement("privilege not permitted for this grantee and object")


def _create_check(n: str, bare: str):
    if bare.startswith("CREATE DATABASE "):
        if not re.fullmatch(r"CREATE DATABASE SZL_EE_DB DATA_RETENTION_TIME_IN_DAYS = 1( COMMENT = '')?", bare):
            raise K.RefusedStatement("CREATE DATABASE form not permitted")
    elif bare.startswith("CREATE SCHEMA "):
        if not re.fullmatch(r"CREATE SCHEMA SZL_EE_DB\.EE_(DATA|APP) WITH MANAGED ACCESS "
                            r"DATA_RETENTION_TIME_IN_DAYS = 1( COMMENT = '')?", bare):
            raise K.RefusedStatement("CREATE SCHEMA form not permitted")
    elif bare.startswith("CREATE TABLE "):
        if not re.match(r"CREATE TABLE SZL_EE_DB\.EE_DATA\." + _IDENT + r" ?\(", bare):
            raise K.RefusedStatement("CREATE TABLE must name SZL_EE_DB.EE_DATA.<table>")
        if _TABLE_DENY.search(bare):
            raise K.RefusedStatement("table option not permitted (background cost or policy)")
        if any(v != "1" for v in re.findall(r"\bDATA_RETENTION_TIME_IN_DAYS\s*=\s*(\S+)", bare)):
            raise K.RefusedStatement("DATA_RETENTION_TIME_IN_DAYS must be 1")
    elif bare.startswith("CREATE STAGE "):
        if n != K.normalize_sql(STAGE_SQL):
            raise K.RefusedStatement("CREATE STAGE differs from the kit statement")
    elif bare.startswith("CREATE STREAMLIT "):
        if n != K.normalize_sql(STREAMLIT_SQL):
            raise K.RefusedStatement("CREATE STREAMLIT differs from the kit statement")
    elif bare.startswith("PUT "):
        if not _PUT_RX.fullmatch(n):
            raise K.RefusedStatement("PUT form not permitted")


def deploy_check(stmt: str):
    """Guard applied to EVERY statement before execution.

    Statement type is checked on the full text; deny tokens are checked with
    quoted literals and $$ blocks blanked (a literal cannot execute, and a
    local path such as ...\\task-7 must not trip the TASK token)."""
    _lexical_check(stmt)
    n = K.normalize_sql(stmt)
    bare = _strip_literals(n)
    if ";" in bare:
        raise K.RefusedStatement("multiple statements")
    if n == K.normalize_sql(CONTEXT_SQL):
        return
    if not _ALLOWED_PREFIX.match(n):
        raise K.RefusedStatement("statement type not permitted")
    for rx in _DENY:
        if rx.search(bare):
            if rx.pattern == r"\bRESOURCE\s+MONITORS?\b" and bare.startswith("SHOW RESOURCE MONITORS LIKE "):
                continue
            raise K.RefusedStatement("denied token: " + rx.pattern)
    if "OWNERSHIP" in bare and n not in OWNERSHIP_SQL:
        raise K.RefusedStatement("ownership transfer not permitted")
    if bare.startswith("GRANT "):
        _grant_check(n, bare)
    _create_check(n, bare)
    if bare.startswith("CREATE TABLE ") and re.search(r"\bAS\s*\(?\s*(SELECT|WITH)\b", bare):
        raise K.RefusedStatement("CREATE TABLE AS SELECT not permitted (needs compute)")
    for m in _QUALIFIED.finditer(bare):
        parts = [x for x in m.groups() if x]
        if len(parts) == 3 and not (parts[0] == "SZL_EE_DB" and parts[1] in ("EE_DATA", "EE_APP")):
            raise K.RefusedStatement("three-part name outside SZL_EE_DB.EE_DATA / EE_APP")


def _strip_literals(s: str) -> str:
    s = re.sub(r"\$\$.*?\$\$", "$$$$", s, flags=re.S)
    return re.sub(r"'(?:[^']|'')*'", "''", s)


def split_sql(text: str) -> list:
    """Split SQL into statements, dropping -- and /* */ comments; respects '...' and $$...$$."""
    out, buf, i, n = [], [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("--", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise K.RefusedStatement("unterminated block comment")
            i = j + 2
            buf.append(" ")
            continue
        if c == "'":
            j = i + 1
            while True:
                if j >= n:
                    raise K.RefusedStatement("unterminated string literal")
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            buf.append(text[i:j + 1])
            i = j + 1
            continue
        if text.startswith("$$", i):
            j = text.find("$$", i + 2)
            if j < 0:
                raise K.RefusedStatement("unterminated $$ block")
            buf.append(text[i:j + 2])
            i = j + 2
            continue
        if c == ";":
            s = "".join(buf).strip()
            if s:
                out.append(s)
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    s = "".join(buf).strip()
    if s:
        out.append(s)
    return out


_QUALIFIED = re.compile(r"\b([A-Z_][A-Z0-9_$]*)\s*\.\s*([A-Z_][A-Z0-9_$]*)(?:\s*\.\s*([A-Z_][A-Z0-9_$]*))?")


def bind_guard(kind: str, text: str, approval_sha: str | None) -> tuple:
    """Handle the SQL/app track's fail-closed first line. The pinned digest is
    over the file as delivered; the guard is replaced IN MEMORY only, bound to
    the approval file's sha256. Returns (text, note)."""
    lines = text.splitlines()
    idx = next((i for i, l in enumerate(lines) if l.strip()), None)
    if idx is None:
        raise K.RefusedStatement("%s is empty" % kind)
    first = lines[idx].strip()
    rest = "\n".join(lines[idx + 1:])
    if GUARD_LINE in rest:
        raise K.RefusedStatement("%s: guard token outside the first line" % kind)
    if first == GUARD_LINE:
        ref = approval_sha or "<bound at --execute>"
        lines[idx] = "-- DEPLOYMENT_APPROVAL_REF: %s" % ref
        return "\n".join(lines), "guard line bound in memory to approval sha256 %s" % ref
    m = _GUARD_REF.fullmatch(first)
    if m:
        if approval_sha and m.group("h") != approval_sha:
            raise K.RefusedStatement("%s: approval reference does not match the approval file" % kind)
        return text, "approval reference present in file"
    return text, "no guard line"


def validate_file_statements(kind: str, stmts: list) -> list:
    if not stmts:
        raise K.RefusedStatement("%s contains no statements" % kind)
    rx = _FILE_PREFIX[kind]
    for s in stmts:
        if not rx.match(K.normalize_sql(s)):
            raise K.RefusedStatement("%s: statement type not permitted in this file" % kind)
        deploy_check(s)
    return stmts


def check_app_imports(app_path: str, pinned: set):
    """Refuse if streamlit_app.py imports a sibling module whose file is not pinned."""
    import ast
    with open(app_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    base = os.path.dirname(app_path)
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module.split(".")[0]]
        for nm in names:
            if os.path.exists(os.path.join(base, nm + ".py")) and (nm + ".py") not in pinned:
                raise K.RefusedStatement("streamlit_app.py imports unpinned local module " + nm)


def parse_approval(raw: bytes, today: _dt.date) -> dict:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise K.RefusedStatement("approval file has a BOM")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise K.RefusedStatement("approval file is not UTF-8") from None
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if "\n" in text or "\r" in text:
        raise K.RefusedStatement("approval must be exactly one line")
    m = _APPROVAL_RE.fullmatch(text)
    if not m:
        raise K.RefusedStatement("approval text does not match the template exactly")
    n = int(m.group("n"))
    if n > CAP_CREDITS:
        raise K.RefusedStatement("approved credits exceed the kit cap of %d" % CAP_CREDITS)
    try:
        until = _dt.date.fromisoformat(m.group("d"))
    except ValueError:
        raise K.RefusedStatement("approval date is not a valid date") from None
    if until <= today:
        raise K.RefusedStatement("approval date is not in the future (UTC)")
    if (until - today).days > MAX_WINDOW_DAYS:
        raise K.RefusedStatement("approval window exceeds %d days" % MAX_WINDOW_DAYS)
    return {"credits": n, "until": until.isoformat(), "account": m.group("a").upper(),
            "approval_sha256": K.sha256_text(text)}


_HEX64 = re.compile(r"[0-9a-f]{64}")


def load_manifest(path: str) -> dict:
    """Accepts {"files": {name: hex | {"sha256": hex, "path": rel}}} or
    {"files": [{"path": rel, "sha256": hex}, ...]}. Paths are relative to the
    manifest directory and may not escape it. Required: schema.sql,
    reader_grants.sql, streamlit_app.py. Optional: evidence_core.py."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        raise K.RefusedStatement("manifest unreadable or not JSON") from None
    files = data.get("files") if isinstance(data, dict) else None
    entries = []
    if isinstance(files, dict):
        for name, v in files.items():
            if isinstance(v, str):
                entries.append((name, v))
            elif isinstance(v, dict):
                entries.append((v.get("path", name), v.get("sha256")))
    elif isinstance(files, list):
        for v in files:
            if isinstance(v, dict):
                entries.append((v.get("path"), v.get("sha256")))
    base = os.path.dirname(os.path.abspath(path))
    found = {}
    for rel, digest in entries:
        if not isinstance(rel, str) or not isinstance(digest, str):
            raise K.RefusedStatement("manifest entry malformed")
        name = os.path.basename(rel.replace("\\", "/"))
        if name not in REQUIRED_FILES + OPTIONAL_APP_FILES:
            continue
        if os.path.isabs(rel) or ".." in rel.replace("\\", "/").split("/"):
            raise K.RefusedStatement("manifest path escapes the manifest directory")
        if not _HEX64.fullmatch(digest.lower()):
            raise K.RefusedStatement("manifest digest is not sha256 hex")
        if name in found:
            raise K.RefusedStatement("manifest lists %s twice" % name)
        found[name] = (os.path.join(base, rel), digest.lower())
    missing = [r for r in REQUIRED_FILES if r not in found]
    if missing:
        raise K.RefusedStatement("manifest missing: " + ", ".join(missing))
    for name, (fp, digest) in found.items():
        try:
            actual = K.sha256_file(fp)
        except OSError:
            raise K.RefusedStatement("manifest file not found: " + name) from None
        if actual != digest:
            raise K.RefusedStatement("digest mismatch for " + name)
    return found


def manual_accountadmin_block(approval) -> list:
    """Owner-only SQL the kit never runs (D0 + D3 grants), mirrored by SNOWSIGHT_SETUP.sql.
    User creation (D1), key registration (D2) and D4/D4b are in SNOWSIGHT_SETUP.sql only."""
    n = str(approval["credits"]) if approval else "<N>"
    d = approval["until"] if approval else "<UTC date>"
    out = [
        "-- D0 (owner, ACCOUNTADMIN): monitor + warehouse. ACCOUNTADMIN is genuinely required for both:",
        "-- only ACCOUNTADMIN can create a resource monitor or assign a warehouse to one (Snowflake docs).",
        "-- A resource monitor is NOT a hard spending cap: see COST_AND_SHUTDOWN.md.",
        "USE ROLE ACCOUNTADMIN",
        ("CREATE RESOURCE MONITOR %s WITH CREDIT_QUOTA = %s FREQUENCY = NEVER START_TIMESTAMP = IMMEDIATELY "
         "END_TIMESTAMP = '%s 23:59:00 +00:00' TRIGGERS ON 50 PERCENT DO NOTIFY ON 75 PERCENT DO NOTIFY "
         "ON 90 PERCENT DO SUSPEND ON 100 PERCENT DO SUSPEND_IMMEDIATE") % (RM, n, d),
        WAREHOUSE_SQL,
        "-- D0 (owner, USERADMIN): the six pilot roles",
        "USE ROLE USERADMIN",
    ]
    out += ["CREATE ROLE %s COMMENT = '%s'" % (r, ROLE_COMMENTS[r]) for r in ROLES]
    role = None
    for decision, executor, stmt in OWNER_RUN_GRANTS:
        if "TO USER " in stmt:
            continue  # D3/D4/D4b user grants: SNOWSIGHT_SETUP.sql, after D1/D2
        if executor != role:
            out.append("USE ROLE %s" % executor)
            role = executor
        out.append(stmt)
    out.append("-- D1 users, D2 keys, and the D3/D4/D4b user grants: SNOWSIGHT_SETUP.sql (owner only).")
    return out


def build_plan(files: dict | None) -> list:
    """Ordered (step, statement) list executed by the kit. v0.3.0: no ACCOUNTADMIN, SYSADMIN,
    USERADMIN, CREATE ROLE or CREATE WAREHOUSE; schema.sql v4 starts with USE ROLE SZL_EE_SETUP."""
    p = []
    a = p.append
    if files:
        for s in files["schema.sql"]:
            a(("B5-B8 schema.sql", s))
    else:
        a(("B5-B8 schema.sql", "-- <statements of schema.sql v4 (database as SZL_EE_SETUP, managed-access schemas, "
                               "tables, grants as SZL_EE_OWNER); sha256 pinned in MANIFEST.json>"))
    a(("B9", "USE ROLE SZL_EE_OWNER"))
    a(("B9", STAGE_SQL))
    a(("B9", "GRANT READ ON STAGE %s TO ROLE SZL_EE_APP" % STAGE))
    uploads = (files or {}).get("_uploads") or ["<path of streamlit_app.py from MANIFEST.json>"]
    for up in uploads:
        a(("B10", "PUT 'file://%s' @%s/v1 AUTO_COMPRESS = FALSE OVERWRITE = FALSE" % (up, STAGE)))
    a(("B12", "USE ROLE SZL_EE_APP"))
    a(("B12", STREAMLIT_SQL))
    if files:
        for s in files["reader_grants.sql"]:
            a(("B13 reader_grants.sql", s))
    else:
        a(("B13 reader_grants.sql", "-- <statements of reader_grants.sql; sha256 pinned in MANIFEST.json>"))
    return p


MANUAL_AFTER = [
    "-- Manual, owner only (not executed by the kit):",
    "-- USE ROLE USERADMIN; GRANT ROLE SZL_EE_VIEWER TO USER <APPROVED_VIEWER_USER>;   (AP-F3, separate approval)",
    "-- Fixture load B11 runs as SZL_EE_RUNTIME (role SZL_EE_INGEST) inside an approved window (AP-B3, AP-E1).",
    "-- A compute window is opened by SZL_EE_RUNTIME with SZL_EE_OPERATOR (RESUME/SUSPEND only; D4b, separate",
    "-- approval). AUTO_RESUME stays FALSE; see PERSISTENT_ACCESS_PROPOSAL.md.",
]


class _ArgError(Exception):
    pass


def _parse_args(argv):
    opts = {"execute": False, "dry_run": False, "approval": None, "manifest": None, "out": None}
    it = iter(argv)
    for tok in it:
        if tok == "--execute":
            opts["execute"] = True
        elif tok == "--dry-run":
            opts["dry_run"] = True
        elif tok in ("--approval-file", "--manifest", "--out"):
            try:
                opts[{"--approval-file": "approval", "--manifest": "manifest", "--out": "out"}[tok]] = next(it)
            except StopIteration:
                raise _ArgError("missing value for " + tok) from None
        else:
            raise _ArgError("unknown argument (connection parameters are never accepted on argv)")
    if opts["execute"] and opts["dry_run"]:
        raise _ArgError("--execute and --dry-run are exclusive")
    return opts


def _prepare(opts, today):
    approval = files = None
    notes = []
    if opts["approval"]:
        with open(opts["approval"], "rb") as f:
            approval = parse_approval(f.read(), today)
    if opts["manifest"]:
        found = load_manifest(opts["manifest"])
        files = {}
        for kind in ("schema.sql", "reader_grants.sql"):
            with open(found[kind][0], "r", encoding="utf-8") as f:
                text, note = bind_guard(kind, f.read(), approval["approval_sha256"] if approval else None)
            notes.append("%s: %s" % (kind, note))
            files[kind] = validate_file_statements(kind, split_sql(text))
        check_app_imports(found["streamlit_app.py"][0], set(found))
        uploads = []
        for kind in ("streamlit_app.py",) + OPTIONAL_APP_FILES:
            if kind in found:
                up = os.path.abspath(found[kind][0]).replace("\\", "/")
                if "'" in up:
                    raise K.RefusedStatement("upload path contains a quote")
                uploads.append(up)
        files["_uploads"] = uploads
        files["_digests"] = {k: v[1] for k, v in found.items()}
        files["_paths"] = {k: v[0] for k, v in found.items()}
    plan = build_plan(files)
    for step, s in plan:
        if not s.startswith("--"):
            deploy_check(s)
    return approval, files, plan, notes


def _exact(rows, names):
    return [r for r in rows if str(r.get("name", "")).upper() in names]


def _norm_size(v):
    return str(v or "").upper().replace("-", "").replace("_", "").replace(" ", "")


def warehouse_problems(row: dict, params: dict) -> list:
    """v0.3.0: properties of the owner-created SZL_EE_WH that differ from EXPECTED_WAREHOUSE /
    EXPECTED_WH_PARAMS (missing counts as different). Cluster counts are checked when SHOW
    WAREHOUSES returns those columns (edition-dependent; UNKNOWN live)."""
    bad = []
    if str(row.get("state", "")).upper() != EXPECTED_WAREHOUSE["state"]:
        bad.append("state")
    if _norm_size(row.get("size")) != EXPECTED_WAREHOUSE["size"]:
        bad.append("size")
    if "auto_resume" not in row or K.truthy(row.get("auto_resume")):
        bad.append("auto_resume")
    if str(row.get("auto_suspend")) != EXPECTED_WAREHOUSE["auto_suspend"]:
        bad.append("auto_suspend")
    if str(row.get("resource_monitor", "")).upper() != EXPECTED_WAREHOUSE["resource_monitor"]:
        bad.append("resource_monitor")
    if str(row.get("owner", "")).upper() != EXPECTED_WAREHOUSE["owner"]:
        bad.append("owner")
    if str(row.get("type", "")).upper() != EXPECTED_WAREHOUSE["type"]:
        bad.append("type")
    for col in ("min_cluster_count", "max_cluster_count"):
        if col in row and str(row.get(col)) != "1":
            bad.append(col)
    for key, want in EXPECTED_WH_PARAMS.items():
        if str(params.get(key)) != want:
            bad.append(key)
    return bad


def identity_problems(raw) -> list:
    """v0.3.0: CURRENT_AVAILABLE_ROLES() (JSON list, includes inherited roles) must contain
    SZL_EE_SETUP and no admin role and no runtime/viewer role."""
    try:
        roles = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        roles = None
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        return ["CURRENT_AVAILABLE_ROLES unreadable"]
    up = {r.upper() for r in roles}
    bad = []
    if SETUP_ROLE not in up:
        bad.append("SZL_EE_SETUP not available")
    adm = sorted(up & ADMIN_ROLES)
    if adm:
        bad.append("admin role reachable: " + ",".join(adm))
    rt = sorted(up & NOT_FOR_SETUP)
    if rt:
        bad.append("runtime/viewer role reachable by the setup identity: " + ",".join(rt))
    return bad


def _executed(sess):
    return [{"statement": e["statement"], "query_id": e["query_id"]} for e in sess.executed]


def main(argv=None, connector=None, env=None, out=None, today=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    ev = {"kit": K.KIT_NAME, "kit_version": K.KIT_VERSION, "script": "sf_deploy_pilot",
          "started_utc": K.utc_now(), "mode": None, "refusals": [], "executed": [], "post_checks": []}
    try:
        opts = _parse_args(argv)
    except _ArgError as exc:
        ev["refusals"].append(str(exc))
        ev["exit_code"] = K.EXIT_REFUSED
        K.emit(ev, env, out)
        return K.EXIT_REFUSED
    ev["mode"] = "execute" if opts["execute"] else "dry-run"
    try:
        approval, files, plan, notes = _prepare(opts, today)
    except (K.RefusedStatement, OSError, SyntaxError) as exc:
        ev["refusals"].append(str(exc) if isinstance(exc, K.RefusedStatement) else "file error: " + type(exc).__name__)
        ev["exit_code"] = K.EXIT_REFUSED
        K.emit(ev, env, out, opts["out"])
        return K.EXIT_REFUSED

    if not opts["execute"]:
        out.write("# DRY RUN - nothing executed; the Snowflake connector was not loaded.\n")
        if approval:
            out.write("# approval: credits=%d until=%s approval_sha256=%s (account redacted)\n"
                      % (approval["credits"], approval["until"], approval["approval_sha256"]))
        if files:
            for kind, dg in sorted(files["_digests"].items()):
                out.write("# pinned: %s sha256 %s\n" % (kind, dg))
        for nt in notes:
            out.write("# note: %s\n" % nt)
        out.write("# OWNER BLOCK D0 + D3 GRANTS - RUN MANUALLY IN SNOWSIGHT (the kit never runs this block; "
                  "SNOWSIGHT_SETUP.sql is the full sheet):\n")
        for s in manual_accountadmin_block(approval):
            out.write(s + (";\n" if not s.startswith("--") else "\n"))
        out.write("# STEPS EXECUTED BY THE KIT WITH --execute (in this order, after preflight checks):\n")
        for step, s in plan:
            out.write("[%s] %s%s\n" % (step, s, "" if s.startswith("--") else ";"))
        for s in MANUAL_AFTER:
            out.write(s + "\n")
        return K.EXIT_OK

    if not approval or not files:
        ev["refusals"].append("--execute requires --approval-file and --manifest")
        ev["exit_code"] = K.EXIT_REFUSED
        K.emit(ev, env, out, opts["out"])
        return K.EXIT_REFUSED
    try:
        ev["run_id"] = K.run_id(env)
    except K.RefusedStatement as exc:
        ev["refusals"].append(str(exc))
        ev["exit_code"] = K.EXIT_REFUSED
        K.emit(ev, env, out, opts["out"])
        return K.EXIT_REFUSED
    ev["approval"] = {"credits": approval["credits"], "until": approval["until"],
                      "account": K.redact_identifier(approval["account"]),
                      "approval_sha256": approval["approval_sha256"]}
    ev["manifest_digests"] = files["_digests"]
    ev["notes"] = notes
    # v0.3.0: --out becomes a progress file, rewritten (fsync) before and after every statement.
    progress = None
    if opts["out"]:
        try:
            progress = K.ProgressFile(opts["out"], env)
        except FileExistsError:
            ev["refusals"].append("--out file already exists; it is never overwritten")
            ev["exit_code"] = K.EXIT_REFUSED
            K.emit(ev, env, out)
            return K.EXIT_REFUSED

    def save():
        if progress is not None:
            progress.write(ev)

    def finish(code):
        ev["in_progress"] = False
        ev["finished_utc"] = K.utc_now()
        ev["exit_code"] = code
        K.emit(ev, env, out)
        save()
        return code

    ev["in_progress"] = True
    ev["phase"] = "connect"
    ev["pending"] = None
    save()
    if connector is None:
        try:
            connector = K.load_connector()
        except K.ConnectorUnavailable as exc:
            ev["connection"] = {"status": "CONNECTOR_NOT_INSTALLED", "error_class": str(exc)}
            return finish(K.EXIT_CONNECTION)
    try:
        conn = K.connect(connector, env, "szl-ee-kit-deploy")
    except Exception as exc:
        ev["connection"] = dict(status="CONNECTION_FAILED", **K.safe_error(exc))
        return finish(K.EXIT_CONNECTION)
    sess = K.GuardedSession(conn, deploy_check)
    code = K.EXIT_OK
    changes_begun = False
    try:
        def refuse(msg):
            raise K.RefusedStatement(msg)
        # ---- preflight (read-only) ----
        ev["phase"] = "preflight"
        save()
        sess.run("USE SECONDARY ROLES NONE")
        cur, _ = sess.run("SHOW WAREHOUSES")
        gate = K.warehouse_gate(K.rows_as_dicts(cur))
        ev["warehouse_gate"] = gate
        if not gate["allowed"]:
            refuse("account check would risk resuming a warehouse: " + gate["reason"])
        cur, _ = sess.run(CONTEXT_SQL)
        rows = cur.fetchall() or []
        acct, org, name, avail = (list(rows[0]) + [None] * 4)[:4] if rows else (None, None, None, None)
        cands = {str(acct).upper()} if acct else set()
        if org and name:
            cands.add(("%s-%s" % (org, name)).upper())
        if approval["account"] not in cands:
            refuse("approved account does not match the connected account")
        ev["account_match"] = True
        problems = identity_problems(avail)
        if problems:
            refuse("connected identity is not the narrow setup identity: " + "; ".join(problems))
        ev["identity_check"] = "PASS"
        sess.run("USE ROLE " + SETUP_ROLE)
        cur, _ = sess.run("SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM'")
        # LIKE treats '_' as a wildcard: keep exact-name rows only
        mons = _exact(K.rows_as_dicts(cur), {RM})
        if len(mons) != 1:
            refuse("resource monitor SZL_EE_RM must exist first (owner block D0)")
        mon = mons[0]
        try:
            quota = float(mon.get("credit_quota"))
        except (TypeError, ValueError):
            refuse("cannot read credit_quota of SZL_EE_RM")
        if quota != float(approval["credits"]) or quota > CAP_CREDITS:
            refuse("SZL_EE_RM credit_quota does not equal the approved credits")
        if str(mon.get("frequency", "")).upper() != "NEVER":
            refuse("SZL_EE_RM frequency must be NEVER")
        cur, _ = sess.run("SHOW WAREHOUSES LIKE 'SZL_EE_WH'")
        whs = _exact(K.rows_as_dicts(cur), {WH})
        if len(whs) != 1:
            refuse("owner-created warehouse SZL_EE_WH must exist first (owner block D0)")
        cur, _ = sess.run(SHOW_PARAMS_SQL)
        params = {str(r.get("key", "")).upper(): str(r.get("value")) for r in K.rows_as_dicts(cur)}
        bad = warehouse_problems(whs[0], params)
        ev["warehouse_check"] = {"problems": bad}
        if bad:
            refuse("SZL_EE_WH differs from the owner spec: " + ", ".join(bad))
        cur, _ = sess.run("SHOW DATABASES LIKE 'SZL_EE_DB'")
        if _exact(K.rows_as_dicts(cur), {DB}):
            refuse("object already exists: SZL_EE_DB")
        cur, _ = sess.run("SHOW ROLES LIKE 'SZL_EE_%'")
        found = [str(r.get("name", "")).upper() for r in K.rows_as_dicts(cur)]
        missing = [r for r in ROLES if found.count(r) != 1]
        if missing:
            refuse("owner-created roles missing (owner block D0): " + ", ".join(missing))
        # re-verify file digests immediately before use
        for kind, fp in files["_paths"].items():
            if K.sha256_file(fp) != files["_digests"][kind]:
                refuse("digest changed since preflight: " + kind)
        ev["phase"] = "changes"
        ev["executed"] = _executed(sess)
        save()
        # ---- changes: progress is written BEFORE each statement (pending) and after it ----
        for idx, (step, s) in enumerate(plan):
            if s.startswith("--"):
                continue
            changes_begun = True
            ev["pending"] = {"index": idx, "step": step, "statement": s,
                             "statement_sha256": K.sha256_text(s), "started_utc": K.utc_now()}
            save()
            try:
                sess.run(s)
            except K.RefusedStatement:
                raise
            except Exception as exc:
                ev["failed_step"] = dict(step=step, statement_sha256=K.sha256_text(s), **K.safe_error(exc))
                code = K.EXIT_EXEC_ERROR
                break
            ev["pending"] = None
            ev["executed"] = _executed(sess)
            save()
        if code == K.EXIT_OK:
            ev["phase"] = "post_checks"
            sess.run("USE ROLE " + SETUP_ROLE)
            cur, qid = sess.run("SHOW WAREHOUSES LIKE 'SZL_EE_WH'")
            w = (_exact(K.rows_as_dicts(cur), {WH}) or [{}])[0]
            for check, ok in (("warehouse SUSPENDED", str(w.get("state", "")).upper() == "SUSPENDED"),
                              ("auto_resume false", not K.truthy(w.get("auto_resume"))),
                              ("resource_monitor SZL_EE_RM", str(w.get("resource_monitor", "")).upper() == RM),
                              ("auto_suspend 60", str(w.get("auto_suspend")) == "60")):
                ev["post_checks"].append({"check": check, "status": "PASS" if ok else "FAIL", "query_id": qid})
    except K.RefusedStatement as exc:
        ev["refusals"].append(str(exc))
        code = K.EXIT_EXEC_ERROR if changes_begun else K.EXIT_REFUSED
    except Exception as exc:
        ev["error"] = K.safe_error(exc)
        code = K.EXIT_EXEC_ERROR if changes_begun else K.EXIT_REFUSED
    finally:
        try:
            conn.close()
        except Exception:
            pass
    ev["executed"] = _executed(sess)
    ev["changes_begun"] = changes_begun
    ev["readback_required"] = bool(changes_begun and code != K.EXIT_OK)
    ev["phase"] = "done"
    ev["note"] = "Nothing is rolled back or dropped automatically; see DEPLOYMENT_PLAN.md section 2."
    return finish(code)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
    sys.exit(main())
