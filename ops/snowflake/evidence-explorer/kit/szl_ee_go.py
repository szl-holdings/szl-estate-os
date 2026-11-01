#!/usr/bin/env python3
"""SZL Evidence Explorer pilot 1 - one-command live run. v0.3.0 DRAFT (narrow design).

DRAFT_READY, NOT LOCAL_TESTED. Running this against Snowflake is NOT authorized
(review brief 2026-10-22). Design: PERSISTENT_ACCESS_PROPOSAL.md (89654200) plus
lead decision D4b (role SZL_EE_OPERATOR with OPERATE on SZL_EE_WH, granted only to
SZL_EE_RUNTIME; NOT APPROVED).

Two identities, never an admin role:
  setup   profile szl_ee_setup   user SZL_EE_DEPLOY   role SZL_EE_SETUP   no warehouse
          -> verify, identity, inventory, dry run, deploy, post-run object readback
  runtime profile szl_ee_runtime user SZL_EE_RUNTIME  role SZL_EE_INGEST  warehouse SZL_EE_WH
          -> identity, RESUME/SUSPEND (secondary role SZL_EE_OPERATOR), integration tests,
             warehouse readback, shutdown verifier
Neither profile names SYSADMIN, USERADMIN, SECURITYADMIN or ACCOUNTADMIN; the run is
refused if either session reports one of them among its available roles.

Order (fail-closed; any failure or uncertain outcome stops the forward path):
  0 start     unique run id; out dir <--out>/szl_ee_run_<run_id> (never reused)
  1 pins      KIT_SHA256SUMS.txt == --kit-sums-sha256 and every sf_*.py matches it;
              MANIFEST.json == --manifest-sha256 and the bundle files the runner
              executes are pinned in it and match. Re-checked before every child.
  2 prereq    snowflake.snowpark importable by the interpreter that runs the live
              tests; else BLOCKED before any credential
  3 creds     two temporary profiles (mode A) or two owner connection names (mode B)
  4 verify    sf_verify_account_readonly.py (setup profile)
  5 identity  both profiles: approved account, distinct users, exact primary role,
              no forbidden available role, runtime has SZL_EE_OPERATOR available
  6 inventory read-only SHOW ... LIKE + exact post-filter (setup profile). REFUSES if
              SZL_EE_DB, the app or the stage exist; REQUIRES owner-created SZL_EE_RM
              (exactly once) and SZL_EE_WH (SUSPENDED, auto_resume false, monitor
              SZL_EE_RM, owner ACCOUNTADMIN)
  7 dryrun    sf_deploy_pilot.py --dry-run (setup profile env; no connection)
  8 deploy    sf_deploy_pilot.py --execute (setup profile); post_checks must PASS
  9 resume    USE SECONDARY ROLES SZL_EE_OPERATOR; ALTER WAREHOUSE SZL_EE_WH RESUME IF SUSPENDED
 10 itests    test_integration_snowflake.py --live-approved -v (runtime profile); parsed PER TEST
--dry-run-only returns before steps 2-6. It runs step 7 in an environment with
no inherited Snowflake credentials, does not import the connector, and sends no SQL.
  ALWAYS once step 8 has started (deadline, exception or Ctrl-C included):
 11 suspend   USE SECONDARY ROLES SZL_EE_OPERATOR; ALTER WAREHOUSE SZL_EE_WH SUSPEND
 12 readback  setup-profile object inventory + runtime-profile warehouse SHOW
 13 shutdown  sf_shutdown_verify.py (runtime profile, separate process)
 14 billable  potentially_billable.json
 15 cleanup   temporary credential directory removed (file NAMES recorded first)

Never: automatic retry, DROP/REPLACE/overwrite, a second deploy in the same run.
Uncertain outcome -> readback, exit 6. Failed/unverified shutdown -> FAIL + billable list.

Credentials (never on argv, never printed, never passed to child env):
  A) env SNOWFLAKE_ACCOUNT; SNOWFLAKE_DEPLOY_USER + SNOWFLAKE_DEPLOY_PRIVATE_KEY;
     SNOWFLAKE_RUNTIME_USER + SNOWFLAKE_RUNTIME_PRIVATE_KEY (unencrypted PKCS#8 PEM,
     two different users and two different keys) -> temporary SNOWFLAKE_HOME.
  B) env SZL_SF_SETUP_CONNECTION_NAME + SZL_SF_RUNTIME_CONNECTION_NAME (owner's config).
  The v0.2 single-identity variables are refused.
Kit scripts read SZL_SF_CONNECTION_NAME: the runner sets it to the setup profile for
verify/dry run/deploy and to the runtime profile for the shutdown verifier.
Exit: 0 all PASS; 2 completed with NOT_RUN/UNKNOWN items (never a success);
      1 a step FAILED or shutdown not verified; 3 refused; 4 BLOCKED (no credential,
      connector or live-test prerequisite); 6 uncertain outcome (reconcile by hand).
"""
import datetime as _dt
import hashlib
import json
import os
import re
import secrets as _secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time

RUNNER_VERSION = "0.3.0-draft-20261022"
EXIT_OK, EXIT_FAIL, EXIT_PARTIAL, EXIT_REFUSED, EXIT_BLOCKED, EXIT_UNCERTAIN = 0, 1, 2, 3, 4, 6
EXIT_NOCRED = EXIT_BLOCKED
WAREHOUSE, DATABASE, MONITOR = "SZL_EE_WH", "SZL_EE_DB", "SZL_EE_RM"
WAREHOUSE_OWNER = "ACCOUNTADMIN"
SETUP_ROLE, RUNTIME_ROLE, OPERATOR_ROLE = "SZL_EE_SETUP", "SZL_EE_INGEST", "SZL_EE_OPERATOR"
ROLES = ("SZL_EE_SETUP", "SZL_EE_OWNER", "SZL_EE_INGEST", "SZL_EE_APP", "SZL_EE_VIEWER", "SZL_EE_OPERATOR")
FORBIDDEN_ROLES = frozenset({"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN", "ORGADMIN"})
SETUP_MUST_NOT = FORBIDDEN_ROLES | {"SZL_EE_INGEST", "SZL_EE_OPERATOR"}
RUNTIME_MUST_NOT = FORBIDDEN_ROLES | {"SZL_EE_SETUP", "SZL_EE_OWNER", "SZL_EE_APP"}
RUNTIME_MUST_HAVE = frozenset({OPERATOR_ROLE})
SETUP_PROFILE, RUNTIME_PROFILE = "szl_ee_setup", "szl_ee_runtime"
APP_SCHEMA, APP_NAME, STAGE_NAME = "EE_APP", "SZL_EVIDENCE_EXPLORER", "APP_SRC"
APP_FQN = "%s.%s.%s" % (DATABASE, APP_SCHEMA, APP_NAME)
STAGE_FQN = "%s.%s.%s" % (DATABASE, APP_SCHEMA, STAGE_NAME)
KIT_SUMS_FILE = "KIT_SHA256SUMS.txt"
KIT_REQUIRED = ("sf_verify_account_readonly.py", "sf_deploy_pilot.py", "sf_shutdown_verify.py", "sf_kit_common.py")
BUNDLE_EXECUTED = ("test_integration_snowflake.py", "evidence_core.py", "make_fixture.py")
DEFAULT_MAX_SECONDS = 2700
MIN_MAX_SECONDS, MAX_MAX_SECONDS = 60, 10800
SHUTDOWN_BUDGET_SECONDS = 600
STEP_CAP_SECONDS = 1800
PROBE_CAP_SECONDS = 120
DIRECT_SQL_TIMEOUT = 90
EXPECTED_ITESTS = (
    "test_i01_exact_identity", "test_i02_expected_rows_and_deterministic_queries",
    "test_i03_duplicate_safe_rerun", "test_i04_filters_and_revision_comparison",
    "test_i05_rejected_rows_retained", "test_i06_least_privilege_viewer",
    "test_i07_unauthorized_role_denied", "test_i08_no_unintended_sharing",
    "test_i09_query_ids_and_sanitized_evidence", "test_i10_warehouse_activity_measured_and_suspended",
    "test_i11_app_fails_visibly_without_live_dependency")

# Every statement the runner itself can send. Inventory patterns are deliberately
# BROADER than the exact names (unescaped '_' is a LIKE wildcard, so the pattern is a
# superset); exactness comes from the post-filter. A wrong escape could hide an object.
ALLOWED_DIRECT_SQL = {
    "identity": ("SELECT CURRENT_ACCOUNT() AS A, CURRENT_ORGANIZATION_NAME() AS O, CURRENT_ACCOUNT_NAME() AS N, "
                 "CURRENT_USER() AS U, CURRENT_ROLE() AS R, CURRENT_AVAILABLE_ROLES() AS AR"),
    "inv_warehouses": "SHOW WAREHOUSES LIKE 'SZL%EE%'",
    "inv_databases": "SHOW DATABASES LIKE 'SZL%EE%'",
    "inv_roles": "SHOW ROLES LIKE 'SZL%EE%'",
    "inv_monitors": "SHOW RESOURCE MONITORS LIKE 'SZL%EE%'",
    "inv_streamlits": "SHOW STREAMLITS LIKE 'SZL%EVIDENCE%' IN ACCOUNT",
    "inv_stages": "SHOW STAGES LIKE 'APP%SRC' IN ACCOUNT",
    "operator_on": "USE SECONDARY ROLES SZL_EE_OPERATOR",
    "resume": "ALTER WAREHOUSE SZL_EE_WH RESUME IF SUSPENDED",
    "suspend": "ALTER WAREHOUSE SZL_EE_WH SUSPEND",
}
NO_FETCH = frozenset({"operator_on", "resume", "suspend"})
WAREHOUSE_CONTROL = {"resume": ("operator_on", "resume"), "suspend": ("operator_on", "suspend")}
INVENTORY_KEYS = ("inv_warehouses", "inv_databases", "inv_roles", "inv_monitors", "inv_streamlits", "inv_stages")

_SECRETISH = re.compile(r"(PRIVATE_KEY|PASSWORD|PASSCODE|TOKEN|SECRET|CREDENTIAL|_KEY$)", re.I)
_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
_APPROVAL_ACCOUNT = re.compile(r", account (?P<a>[A-Za-z0-9][A-Za-z0-9_-]{1,63})$")
_ENCRYPTED_HEADER = re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----|^Proc-Type:\s*4\s*,\s*ENCRYPTED", re.M)
_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SUMS_LINE = re.compile(r"^(?P<h>[0-9a-f]{64})  (?P<p>[^\r\n]+)$")
_KIT_PY = re.compile(r"^sf_[A-Za-z0-9_]+\.py$")
MODE_A_VARS = ("SNOWFLAKE_DEPLOY_USER", "SNOWFLAKE_DEPLOY_PRIVATE_KEY", "SNOWFLAKE_RUNTIME_USER",
               "SNOWFLAKE_RUNTIME_PRIVATE_KEY")
MODE_B_VARS = ("SZL_SF_SETUP_CONNECTION_NAME", "SZL_SF_RUNTIME_CONNECTION_NAME")
LEGACY_VARS = ("SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY", "SZL_SF_CONNECTION_NAME", "SZL_SF_INGEST_CONNECTION_NAME")


class Refused(Exception):
    pass


class StepTimeout(Exception):
    """A bounded operation did not finish; its effect on the account is UNKNOWN."""


class DeadlineExceeded(Exception):
    """The global wall clock ran out before a step could start."""


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file_or_none(p):
    try:
        with open(p, "rb") as fh:
            return sha256_bytes(fh.read())
    except OSError:
        return None


def now_utc():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + _secrets.token_hex(4)


def normalize_pem(raw, label="private key"):
    """Accept PKCS#8 PEM with real newlines, literal \\n, or flattened spaces.
    The encryption refusal looks at PEM HEADERS only (see G12 in v0.2)."""
    if not isinstance(raw, str):
        raise Refused("%s missing" % label)
    t = raw.replace("\\n", "\n").strip()
    if _ENCRYPTED_HEADER.search(t):
        raise Refused("encrypted private keys are not supported by this runner (regenerate with -nocrypt)")
    m = re.fullmatch(r"-----BEGIN PRIVATE KEY-----(?P<b>[A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----", t)
    if not m:
        raise Refused("%s is not an unencrypted PKCS#8 PEM block" % label)
    body = re.sub(r"\s+", "", m.group("b"))
    if len(body) < 200:
        raise Refused("%s body too short" % label)
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"


def child_env(base, extra):
    env = {k: v for k, v in base.items() if not _SECRETISH.search(k)}
    for k in LEGACY_VARS + MODE_B_VARS + ("SNOWFLAKE_DEFAULT_CONNECTION_NAME",):
        env.pop(k, None)
    env.update(extra)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def secret_values(base):
    out = []
    for k, v in base.items():
        if _SECRETISH.search(k) and isinstance(v, str) and len(v) >= 4:
            out.append(v)
            out.extend(x for x in re.split(r"\s+|\\n", v) if len(x) >= 16)
    return out


def scrub(text, secrets):
    for s in sorted(set(secrets), key=len, reverse=True):
        if s and s in text:
            text = text.replace(s, "<scrubbed>")
    return text


def _durable_write(path, data, mode="wb"):
    with open(path, mode) as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


class Receipt:
    """Hash-chained, append-only, flushed per entry. Unsigned."""

    def __init__(self, out_dir, secrets, run_id):
        self.out_dir, self.secrets, self.run_id = out_dir, secrets, run_id
        self.logs = os.path.join(out_dir, "logs")
        os.makedirs(self.logs, exist_ok=True)
        self.path = os.path.join(out_dir, "live_run_receipt.jsonl")
        self.state_path = os.path.join(out_dir, "run_state.json")
        self.prev = "0" * 64
        self.entries = []
        self.state = {"run_id": run_id, "deployed": False, "last_step": None, "last_status": None}

    def add(self, step, status, exit_code=None, stdout="", stderr="", detail=""):
        so = scrub(stdout or "", self.secrets).encode("utf-8")
        se = scrub(stderr or "", self.secrets).encode("utf-8")
        n = len(self.entries)
        _durable_write(os.path.join(self.logs, "%02d_%s.stdout" % (n, step)), so)
        _durable_write(os.path.join(self.logs, "%02d_%s.stderr" % (n, step)), se)
        e = {"i": n, "run_id": self.run_id, "step": step, "status": status, "exit_code": exit_code,
             "stdout_sha256": sha256_bytes(so), "stderr_sha256": sha256_bytes(se),
             "detail": scrub(detail if isinstance(detail, str) else json.dumps(detail, sort_keys=True),
                             self.secrets)[:2000],
             "utc": now_utc(), "prev_entry_sha256": self.prev}
        line = json.dumps(e, sort_keys=True, separators=(",", ":"))
        self.prev = sha256_bytes(line.encode("utf-8"))
        self.entries.append(e)
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.state.update(last_step=step, last_status=status, updated_utc=e["utc"], entries=n + 1)
        self.write_state()
        return e

    def begin(self, step, detail=""):
        return self.add(step, "STARTED", detail=detail)

    def write_state(self):
        tmp = self.state_path + ".tmp"
        _durable_write(tmp, json.dumps(self.state, sort_keys=True, indent=1).encode("utf-8"))
        os.replace(tmp, self.state_path)

    def write_json(self, name, obj):
        data = scrub(json.dumps(obj, sort_keys=True, indent=1, default=str), self.secrets).encode("utf-8")
        _durable_write(os.path.join(self.out_dir, name), data)


def verify_chain(path):
    prev = "0" * 64
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            e = json.loads(line)
            if e.get("i") != i or e.get("prev_entry_sha256") != prev:
                return False
            if json.dumps(e, sort_keys=True, separators=(",", ":")) != line.rstrip("\n"):
                return False
            prev = sha256_bytes(line.rstrip("\n").encode("utf-8"))
    return True


def parse_args(argv):
    opts = {"--kit": None, "--bundle": None, "--approval": None, "--out": None,
            "--kit-sums-sha256": None, "--manifest-sha256": None}
    flags, max_seconds = set(), DEFAULT_MAX_SECONDS
    it = iter(argv)
    for a in it:
        if a in opts:
            opts[a] = next(it, None)
        elif a == "--max-seconds":
            v = next(it, None)
            if v is None or not re.fullmatch(r"[0-9]{1,6}", v) or not MIN_MAX_SECONDS <= int(v) <= MAX_MAX_SECONDS:
                raise Refused("--max-seconds must be an integer in [%d, %d]" % (MIN_MAX_SECONDS, MAX_MAX_SECONDS))
            max_seconds = int(v)
        elif a in ("--dry-run-only",):
            flags.add(a)
        else:
            raise Refused("unknown argument (credentials are never accepted on argv)")
    missing = [k for k, v in opts.items() if not v]
    if missing:
        raise Refused("missing " + ", ".join(missing))
    for k in ("--kit-sums-sha256", "--manifest-sha256"):
        opts[k] = opts[k].lower()
        if not _HEX64.match(opts[k]):
            raise Refused(k + " must be a 64-character sha256 hex digest")
    return opts, flags, max_seconds


def approval_account(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8").rstrip("\n").rstrip("\r")
    m = _APPROVAL_ACCOUNT.search(text)
    if not m or "\n" in text:
        raise Refused("approval file has no single-line account field")
    return m.group("a").upper(), sha256_bytes(text.encode("utf-8"))


# ---------------------------------------------------------------- digest pins

def _safe_rel(p):
    q = p.replace("\\", "/")
    return not (os.path.isabs(p) or q.startswith("/") or ".." in q.split("/") or re.match(r"^[A-Za-z]:", q))


def load_kit_sums(kit, expected_sha):
    path = os.path.join(kit, KIT_SUMS_FILE)
    actual = sha256_file_or_none(path)
    if actual is None:
        raise Refused("%s not found in --kit" % KIT_SUMS_FILE)
    if actual != expected_sha:
        raise Refused("%s sha256 does not match --kit-sums-sha256" % KIT_SUMS_FILE)
    with open(path, "rb") as fh:
        text = fh.read().decode("utf-8")
    listed = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _SUMS_LINE.match(line)
        if not m or not _safe_rel(m.group("p")):
            raise Refused("%s has a malformed line" % KIT_SUMS_FILE)
        p = m.group("p").replace("\\", "/")
        if p in listed:
            raise Refused("%s lists %s twice" % (KIT_SUMS_FILE, p))
        listed[p] = m.group("h")
    return listed


def load_manifest_pins(bundle, expected_sha):
    path = os.path.join(bundle, "MANIFEST.json")
    actual = sha256_file_or_none(path)
    if actual is None:
        raise Refused("MANIFEST.json not found in --bundle")
    if actual != expected_sha:
        raise Refused("MANIFEST.json sha256 does not match --manifest-sha256")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except ValueError:
        raise Refused("MANIFEST.json is not JSON") from None
    files = data.get("files") if isinstance(data, dict) else None
    entries = []
    if isinstance(files, dict):
        for name, v in files.items():
            entries.append((v.get("path", name), v.get("sha256")) if isinstance(v, dict) else (name, v))
    elif isinstance(files, list):
        entries = [(v.get("path"), v.get("sha256")) for v in files if isinstance(v, dict)]
    pins = {}
    for rel, dg in entries:
        if not isinstance(rel, str) or not isinstance(dg, str) or not _safe_rel(rel):
            raise Refused("MANIFEST.json entry malformed")
        rel = rel.replace("\\", "/")
        if rel in pins:
            raise Refused("MANIFEST.json lists %s twice" % rel)
        pins[rel] = dg.lower()
    return pins


def check_pins(kit, bundle, kit_sums_sha, manifest_sha):
    """Refuses unless every sf_*.py in --kit and every bundle file the runner executes
    match their pins. Returns {abs path: sha256} for re-checks plus a record."""
    listed = load_kit_sums(kit, kit_sums_sha)
    present = sorted(f for f in os.listdir(kit) if _KIT_PY.match(f) and os.path.isfile(os.path.join(kit, f)))
    for f in KIT_REQUIRED:
        if f not in present:
            raise Refused("required kit file missing: " + f)
    for p in listed:
        if _KIT_PY.match(os.path.basename(p)) and "/" not in p and p not in present:
            raise Refused("kit file listed but missing: " + p)
    pins = {}
    for f in present:
        if f not in listed:
            raise Refused("kit file not listed in %s: %s" % (KIT_SUMS_FILE, f))
        a = sha256_file_or_none(os.path.join(kit, f))
        if a != listed[f]:
            raise Refused("kit file digest mismatch: " + f)
        pins[os.path.join(kit, f)] = a
    mp = load_manifest_pins(bundle, manifest_sha)
    for f in BUNDLE_EXECUTED:
        if f not in mp:
            raise Refused("bundle file executed by the runner is not pinned in MANIFEST.json: " + f)
        a = sha256_file_or_none(os.path.join(bundle, f))
        if a != mp[f]:
            raise Refused("bundle file digest mismatch: " + f)
        pins[os.path.join(bundle, f)] = a
    record = {"kit_sums_sha256": kit_sums_sha, "manifest_sha256": manifest_sha,
              "kit": {f: listed[f] for f in present},
              "bundle": {f: mp[f] for f in BUNDLE_EXECUTED}}
    return pins, record


def recheck_pins(pins, paths):
    """Return the basenames whose current digest differs from the pin (missing = differs)."""
    return [os.path.basename(p) for p in paths if sha256_file_or_none(p) != pins.get(p)]


# ---------------------------------------------------------------- credentials

def materialize(env, tmp):
    """Mode A: two temporary profiles, each with its own key file. Returns profile dict."""
    acct = env.get("SNOWFLAKE_ACCOUNT", "")
    du, ru = env.get("SNOWFLAKE_DEPLOY_USER", ""), env.get("SNOWFLAKE_RUNTIME_USER", "")
    if not (_IDENT.match(acct) and _IDENT.match(du) and _IDENT.match(ru)):
        raise Refused("SNOWFLAKE_ACCOUNT / SNOWFLAKE_DEPLOY_USER / SNOWFLAKE_RUNTIME_USER missing or malformed")
    if du.upper() == ru.upper():
        raise Refused("deploy and runtime users must be two different identities")
    pd = normalize_pem(env.get("SNOWFLAKE_DEPLOY_PRIVATE_KEY"), "deploy private key")
    pr = normalize_pem(env.get("SNOWFLAKE_RUNTIME_PRIVATE_KEY"), "runtime private key")
    if pd == pr:
        raise Refused("deploy and runtime private keys must be different keys")
    ks, kr = os.path.join(tmp, "k_setup.p8"), os.path.join(tmp, "k_runtime.p8")
    for path, pem in ((ks, pd), (kr, pr)):
        with open(path, "w", encoding="ascii", newline="\n") as fh:
            fh.write(pem)
    fs, fr = ks.replace("\\", "/"), kr.replace("\\", "/")
    toml = ("[%s]\naccount = \"%s\"\nuser = \"%s\"\nauthenticator = \"SNOWFLAKE_JWT\"\n"
            "private_key_file = \"%s\"\nrole = \"%s\"\n\n"
            "[%s]\naccount = \"%s\"\nuser = \"%s\"\nauthenticator = \"SNOWFLAKE_JWT\"\n"
            "private_key_file = \"%s\"\nrole = \"%s\"\nwarehouse = \"%s\"\n"
            "database = \"%s\"\nschema = \"EE_DATA\"\n") % (
        SETUP_PROFILE, acct, du, fs, SETUP_ROLE, RUNTIME_PROFILE, acct, ru, fr, RUNTIME_ROLE, WAREHOUSE, DATABASE)
    with open(os.path.join(tmp, "connections.toml"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(toml)
    base = {"account": acct, "authenticator": "SNOWFLAKE_JWT"}
    return {"setup": dict(base, user=du, private_key_file=ks, role=SETUP_ROLE),
            "runtime": dict(base, user=ru, private_key_file=kr, role=RUNTIME_ROLE, warehouse=WAREHOUSE,
                            database=DATABASE, schema="EE_DATA"),
            "setup_name": SETUP_PROFILE, "runtime_name": RUNTIME_PROFILE,
            "extra": {"SNOWFLAKE_HOME": tmp, "SF_SKIP_WARNING_FOR_READ_PERMISSIONS_ON_CONFIG_FILE": "true"}}


def resolve_credentials(env, tmp):
    """Returns the profile dict, or raises Refused; returns None when no credential exists."""
    has_a = any(env.get(k) for k in MODE_A_VARS)
    has_b = any(env.get(k) for k in MODE_B_VARS)
    if has_a and has_b:
        raise Refused("both credential modes present; use exactly one")
    if has_a:
        return materialize(env, tmp)
    if has_b:
        s, r = env.get("SZL_SF_SETUP_CONNECTION_NAME", ""), env.get("SZL_SF_RUNTIME_CONNECTION_NAME", "")
        if not (_IDENT.match(s) and _IDENT.match(r)):
            raise Refused("SZL_SF_SETUP_CONNECTION_NAME and SZL_SF_RUNTIME_CONNECTION_NAME are both required")
        if s == r:
            raise Refused("setup and runtime connection names must differ")
        return {"setup": {"connection_name": s}, "runtime": {"connection_name": r},
                "setup_name": s, "runtime_name": r, "extra": {}}
    if any(env.get(k) for k in LEGACY_VARS):
        raise Refused("the v0.2 single-identity credential contract is retired; see v0.3 docstring")
    return None


# ---------------------------------------------------------------- execution helpers

def run_py(script, args, cwd, env, timeout, runner=subprocess.run):
    """Run a kit/bundle script. subprocess.TimeoutExpired propagates (outcome UNKNOWN)."""
    r = runner([sys.executable, "-I", "-B", script] + list(args), cwd=cwd, env=env,
               capture_output=True, timeout=timeout)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def probe_snowpark(env, timeout, runner=subprocess.run):
    """Import snowflake.snowpark in the same interpreter and flags the live tests use."""
    r = runner([sys.executable, "-I", "-B", "-c", "import snowflake.snowpark"], cwd=None, env=env,
               capture_output=True, timeout=timeout)
    err = r.stderr.decode("utf-8", "replace").strip().splitlines()
    return r.returncode == 0, (err[-1][:200] if err else "")


def bounded(fn, timeout):
    """Run fn in a daemon thread; StepTimeout if it has not finished within `timeout` s."""
    box = {}

    def target():
        try:
            box["v"] = fn()
        except BaseException as exc:      # re-raised in the caller's thread
            box["e"] = exc
    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(max(0.0, timeout))
    if th.is_alive():
        raise StepTimeout("operation still running after %.1f s" % timeout)
    if "e" in box:
        raise box["e"]
    return box["v"]


def direct_sql(connector, conn_kwargs, key, run_id="", timeout=None):
    """Execute ONE fixed statement (or the fixed warehouse-control pair) on its own
    connection. Returns (rows, dict_rows, query_id of the last statement)."""
    seq = WAREHOUSE_CONTROL.get(key, (key,))
    sqls = [ALLOWED_DIRECT_SQL[k] for k in seq]    # KeyError = refused: only fixed statements exist
    kwargs = dict(conn_kwargs)
    kwargs.update({"client_session_keep_alive": False, "login_timeout": 30, "network_timeout": 60,
                   "session_parameters": {"QUERY_TAG": "szl_ee_go:%s:%s" % (run_id, key),
                                          "STATEMENT_TIMEOUT_IN_SECONDS": 60}})

    def work():
        con = connector.connect(**kwargs)
        try:
            cur = None
            for k, sql in zip(seq, sqls):
                cur = con.cursor()
                cur.execute(sql)
            last = seq[-1]
            rows = [] if last in NO_FETCH else list(cur.fetchall() or [])
            names = [str(d[0]).lower() for d in (getattr(cur, "description", None) or [])]
            dicts = [dict(zip(names, r)) for r in rows] if names else []
            return rows, dicts, getattr(cur, "sfqid", None)
        finally:
            con.close()
    return bounded(work, DIRECT_SQL_TIMEOUT if timeout is None else timeout)


def _name(r, col="name"):
    return str(r.get(col, "") or "").upper()


def _truthy(v):
    return str(v).strip().lower() in ("true", "y", "yes", "1", "on")


def parse_roles(v):
    """CURRENT_AVAILABLE_ROLES() returns a JSON array string (REPORTED). Upper-cased set, or None."""
    try:
        lst = json.loads(v) if isinstance(v, str) else v
    except ValueError:
        return None
    if not isinstance(lst, list) or not all(isinstance(x, str) for x in lst):
        return None
    return {x.upper() for x in lst}


def check_identity(row, approved, expected_role, must_not, must_have):
    """row: dict with a,o,n,u,r,ar. Returns (problems, record)."""
    a, o, n = row.get("a"), row.get("o"), row.get("n")
    org_acct = ("%s-%s" % (o, n)).upper() if o and n else None
    problems = []
    if approved not in {str(a).upper(), org_acct}:
        problems.append("account does not match approval")
    role = str(row.get("r") or "").upper()
    if role != expected_role:
        problems.append("primary role is %s, expected %s" % (role or "NONE", expected_role))
    avail = parse_roles(row.get("ar"))
    if avail is None:
        problems.append("available roles unreadable")
        avail = set()
    bad = sorted(avail & set(must_not))
    if bad:
        problems.append("forbidden roles available: " + ", ".join(bad))
    lacking = sorted(set(must_have) - avail)
    if lacking:
        problems.append("required roles not available: " + ", ".join(lacking))
    rec = {"primary_role": role, "available_roles": sorted(avail),
           "user_sha256": sha256_bytes(str(row.get("u") or "").upper().encode("utf-8")),
           "locator_sha256": sha256_bytes(str(a).upper().encode("utf-8")), "problems": problems}
    return problems, rec


def classify_inventory(results):
    """results: {key: dict_rows}. Exact-name post-filter (upper-case)."""
    exact, near = [], []

    def put(kind, r, is_exact, label):
        (exact if is_exact else near).append({"type": kind, "name": label,
                                              "state": r.get("state"), "owner": r.get("owner")})
    for r in results.get("inv_databases", []):
        put("database", r, _name(r) == DATABASE, _name(r))
    for r in results.get("inv_streamlits", []):
        fqn = "%s.%s.%s" % (_name(r, "database_name"), _name(r, "schema_name"), _name(r))
        put("streamlit", r, fqn == APP_FQN, fqn)
    for r in results.get("inv_stages", []):
        fqn = "%s.%s.%s" % (_name(r, "database_name"), _name(r, "schema_name"), _name(r))
        put("stage", r, fqn == STAGE_FQN, fqn)
    near += [{"type": "warehouse", "name": _name(r), "state": r.get("state")}
             for r in results.get("inv_warehouses", []) if _name(r) != WAREHOUSE]
    near += [{"type": "resource_monitor", "name": _name(r)} for r in results.get("inv_monitors", [])
             if _name(r) != MONITOR]
    monitors = [r for r in results.get("inv_monitors", []) if _name(r) == MONITOR]
    whs = [r for r in results.get("inv_warehouses", []) if _name(r) == WAREHOUSE]
    wh = whs[0] if len(whs) == 1 else None
    wh_problems = []
    if len(whs) != 1:
        wh_problems.append("warehouse %s visible %d times (owner creates it in D0)" % (WAREHOUSE, len(whs)))
    else:
        if str(wh.get("state", "")).upper() != "SUSPENDED":
            wh_problems.append("state is %s" % (str(wh.get("state", "")).upper() or "UNKNOWN"))
        if wh.get("auto_resume") is None or _truthy(wh.get("auto_resume")):
            wh_problems.append("auto_resume is not false")
        if _name(wh, "resource_monitor") != MONITOR:
            wh_problems.append("resource_monitor is not %s" % MONITOR)
        if _name(wh, "owner") != WAREHOUSE_OWNER:
            wh_problems.append("owner is not %s" % WAREHOUSE_OWNER)
    return {"existing_pilot_objects": exact, "near_matches": near,
            "monitor_exact_count": len(monitors),
            "monitor": ({k: monitors[0].get(k) for k in ("credit_quota", "used_credits", "frequency",
                                                         "end_time", "level")} if monitors else None),
            "warehouse_exact_count": len(whs), "warehouse_problems": wh_problems,
            "warehouse": ({k: wh.get(k) for k in ("state", "auto_resume", "resource_monitor", "owner",
                                                  "size", "auto_suspend")} if wh else None),
            "warehouse_state": (str(wh.get("state", "")).upper() or "UNKNOWN") if wh else
            ("ABSENT" if not whs else "AMBIGUOUS"),
            "roles_visible": sorted(_name(r) for r in results.get("inv_roles", [])),
            "scope": "objects visible to the session role only; absence here is not proof of absence"}


def take_inventory(connector, direct, run_id, timeout_fn, keys=INVENTORY_KEYS):
    """Read-only. Any error makes the inventory incomplete."""
    results, errors, qids = {}, {}, {}
    for key in keys:
        try:
            _, dicts, qid = direct_sql(connector, direct, key, run_id, timeout=timeout_fn())
            results[key], qids[key] = dicts, qid
        except Exception as exc:
            errors[key] = type(exc).__name__
    rb = classify_inventory(results)
    rb.update({"statements": {k: ALLOWED_DIRECT_SQL[k] for k in keys}, "query_ids": qids,
               "errors": errors, "complete": not errors, "utc": now_utc()})
    return rb


_TEST_LINE = re.compile(r"^(test_i[0-9]{2}_\w+) \([^)]*\) \.\.\. (.+?)\s*$", re.M)


def parse_itests(code, out):
    """Per-test results. PASS only if all eleven expected tests report ok and exit is 0."""
    per = {t: "NOT_RUN" for t in EXPECTED_ITESTS}
    reasons = {t: "no per-test result in output" for t in EXPECTED_ITESTS}
    for m in _TEST_LINE.finditer(out):
        name, res = m.group(1), m.group(2)
        if name not in per:
            continue
        if res == "ok":
            per[name], reasons[name] = "PASS", ""
        elif res.startswith("skipped"):
            per[name], reasons[name] = "NOT_RUN", res[:200]
        else:
            per[name], reasons[name] = "FAIL", res[:200]
    sl = re.search(r"INTEGRATION STATUS: (\w+)", out)
    word = sl.group(1) if sl else None
    vals = list(per.values())
    if "FAIL" in vals or code not in (0, 3) or word == "FAIL":
        overall = "FAIL"
    elif code == 0 and all(v == "PASS" for v in vals) and word in (None, "PASS"):
        overall = "PASS"
    else:
        overall = "NOT_RUN_OR_PARTIAL"
    return {"overall": overall, "exit_code": code, "status_line": word, "tests": per, "reasons": reasons,
            "counts": {s: vals.count(s) for s in ("PASS", "FAIL", "NOT_RUN")}}


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


class _Clock:
    def __init__(self, clock, max_seconds):
        self.clock = clock
        self.deadline = clock() + max_seconds

    def remaining(self):
        return self.deadline - self.clock()

    def step_timeout(self, cap=STEP_CAP_SECONDS):
        r = self.remaining()
        if r <= 0:
            raise DeadlineExceeded("global wall-clock limit reached")
        return min(cap, r)


# ---------------------------------------------------------------- main

def main(argv=None, env=None, connector=None, runner=subprocess.run, clock=time.monotonic):
    env = dict(os.environ if env is None else env)
    try:
        opts, flags, max_seconds = parse_args(sys.argv[1:] if argv is None else argv)
        acct_approved, approval_sha = approval_account(opts["--approval"])
    except (Refused, OSError, UnicodeDecodeError) as exc:
        sys.stdout.write(json.dumps({"exit_code": EXIT_REFUSED, "refusal": str(exc)}) + "\n")
        return EXIT_REFUSED
    run_id = new_run_id()
    out_dir = os.path.join(opts["--out"], "szl_ee_run_" + run_id)
    try:
        if not _RUN_ID.match(run_id):
            raise Refused("malformed run id")
        os.makedirs(opts["--out"], exist_ok=True)
        os.makedirs(out_dir, exist_ok=False)       # never reuse an earlier run's directory
    except (Refused, OSError) as exc:
        sys.stdout.write(json.dumps({"exit_code": EXIT_REFUSED, "refusal": "output directory: " +
                                     type(exc).__name__}) + "\n")
        return EXIT_REFUSED
    rec = Receipt(out_dir, secret_values(env), run_id)
    clk = _Clock(clock, max_seconds)
    rec.add("start", "PASS", detail={
        "run_id": run_id, "runner_version": RUNNER_VERSION, "python": sys.version.split()[0],
        "runner_sha256": sha256_file_or_none(os.path.abspath(__file__)), "approval_sha256": approval_sha,
        "max_seconds": max_seconds, "shutdown_budget_seconds": SHUTDOWN_BUDGET_SECONDS,
        "dry_run_only": "--dry-run-only" in flags})
    state = {"deployed": False, "prof": None, "cenv_setup": None, "cenv_runtime": None, "uncertain": False,
             "connector": connector, "pins": None, "kit": opts["--kit"], "bundle": opts["--bundle"]}
    tmp = None
    code = EXIT_FAIL
    try:
        try:
            pins, record = check_pins(opts["--kit"], opts["--bundle"], opts["--kit-sums-sha256"],
                                      opts["--manifest-sha256"])
        except (Refused, OSError, UnicodeDecodeError) as exc:
            rec.add("pins", "REFUSED", detail=str(exc) if isinstance(exc, Refused) else type(exc).__name__)
            code = EXIT_REFUSED
        else:
            state["pins"] = pins
            rec.write_json("pins.json", record)
            rec.add("pins", "PASS", detail={"kit_sums_sha256": record["kit_sums_sha256"],
                                            "manifest_sha256": record["manifest_sha256"]})
            tmp = tempfile.mkdtemp(prefix="szl_ee_go_")
            code = _prereq_and_forward(opts, flags, env, runner, rec, tmp, state, acct_approved,
                                       approval_sha, clk, run_id)
    finally:
        shutdown_ok = True
        try:
            if state["deployed"]:
                shutdown_ok, partial = _shutdown(opts, state, runner, rec, clock, run_id, code)
                if shutdown_ok and partial and code == EXIT_OK:
                    code = EXIT_PARTIAL
        except (Exception, KeyboardInterrupt) as exc:
            shutdown_ok = False
            rec.add("shutdown_exception", "FAIL", detail=type(exc).__name__)
        finally:
            if tmp is not None:
                names = []
                for dp, _, fs in os.walk(tmp):
                    names += [os.path.relpath(os.path.join(dp, f), tmp) for f in fs]
                shutil.rmtree(tmp, ignore_errors=True)
                gone = not os.path.exists(tmp)
                rec.add("cleanup", "PASS" if gone else "FAIL",
                        detail={"temporary_credential_directory_removed": gone, "file_names_only": sorted(names)})
                if not gone:
                    shutdown_ok = False
            if not shutdown_ok and code in (EXIT_OK, EXIT_PARTIAL, EXIT_REFUSED, EXIT_BLOCKED):
                code = EXIT_FAIL
            overall = {EXIT_OK: "PASS", EXIT_PARTIAL: "INCOMPLETE", EXIT_BLOCKED: "BLOCKED",
                       EXIT_REFUSED: "REFUSED"}.get(code, "FAIL")
            summary = {"run_id": run_id, "out_dir": out_dir, "exit_code": code, "overall": overall,
                       "runner_version": RUNNER_VERSION,
                       "deployed_step_started": state["deployed"],
                       "shutdown_verified": shutdown_ok if state["deployed"] else None,
                       "receipt": rec.path, "chain_valid": verify_chain(rec.path),
                       "steps": [[e["step"], e["status"]] for e in rec.entries]}
            rec.write_json("summary.json", summary)
            sys.stdout.write(json.dumps(summary) + "\n")
    return code


def _offline_dry_run_only(opts, runner, rec, tmp, state, clk):
    """Pilot plan only. No connector import, no credential resolution, no SQL."""
    rec.add("offline_boundary", "PASS", detail={
        "connector_imported": False, "credential_resolution": False, "sql": False})
    manifest = os.path.join(opts["--bundle"], "MANIFEST.json")
    cenv = child_env({}, {"HOME": tmp, "USERPROFILE": tmp, "TEMP": tmp, "TMP": tmp,
                          "SNOWFLAKE_HOME": tmp})
    try:
        c, so, se = _child(rec, "dryrun", "sf_deploy_pilot.py",
                           ["--dry-run", "--manifest", manifest],
                           opts["--kit"], cenv, runner, clk.step_timeout(), state,
                           _kit_paths(state, "sf_deploy_pilot.py"))
    except StepTimeout:
        return EXIT_FAIL
    except Refused:
        return EXIT_REFUSED
    rec.add("dryrun", "PASS" if c == 0 else "FAIL", c, so, se)
    if c != 0:
        return EXIT_FAIL
    return EXIT_PARTIAL


def _prereq_and_forward(opts, flags, env, runner, rec, tmp, state, acct_approved, approval_sha, clk, run_id):
    if "--dry-run-only" in flags:
        return _offline_dry_run_only(opts, runner, rec, tmp, state, clk)
    penv = child_env(env, {"SNOWFLAKE_HOME": tmp, "SZL_EE_RUN_ID": run_id})
    try:
        ok, why = probe_snowpark(penv, min(PROBE_CAP_SECONDS, clk.step_timeout()), runner=runner)
    except subprocess.TimeoutExpired:
        ok, why = False, "probe timed out"
    except (Exception, DeadlineExceeded) as exc:
        ok, why = False, "probe could not run: " + type(exc).__name__
    if not ok:
        rec.add("prerequisites", "BLOCKED", detail={
            "reason": "snowflake.snowpark cannot be imported by %s -I -B; the live integration tests "
                      "would be NOT_RUN, so no deploy is attempted. Nothing was installed." % sys.executable,
            "probe_stderr_tail": why})
        return EXIT_BLOCKED
    rec.add("prerequisites", "PASS", detail="snowflake.snowpark importable by the live-test interpreter")
    if state["connector"] is None:
        # The connector resolves its config directory at import time and raises if none
        # exists, so SNOWFLAKE_HOME must point at the run's temp home BEFORE the import
        # (mode A), or at the owner's own directory (mode B, left untouched).
        saved_home = os.environ.get("SNOWFLAKE_HOME")
        if any(env.get(k) for k in MODE_A_VARS) or not saved_home:
            os.environ["SNOWFLAKE_HOME"] = tmp
        try:
            import snowflake.connector as connector
            state["connector"] = connector
        except ImportError:
            rec.add("connector", "BLOCKED", detail="CONNECTOR_NOT_INSTALLED")
            return EXIT_BLOCKED
        except Exception as exc:
            rec.add("connector", "BLOCKED", detail="CONNECTOR_IMPORT_FAILED:" + type(exc).__name__)
            return EXIT_BLOCKED
    try:
        return _forward(opts, flags, env, state["connector"], runner, rec, tmp, state,
                        acct_approved, approval_sha, clk, run_id)
    except DeadlineExceeded as exc:
        rec.add("deadline", "FAIL", detail=str(exc) + "; no step was running, so nothing is uncertain")
        return EXIT_FAIL
    except (Exception, KeyboardInterrupt) as exc:
        rec.add("runner_exception", "UNKNOWN", detail=type(exc).__name__)
        return EXIT_UNCERTAIN if state["deployed"] else EXIT_FAIL


def _kit_paths(state, script):
    return [os.path.join(state["kit"], script), os.path.join(state["kit"], "sf_kit_common.py")]


def _bundle_paths(state):
    return [os.path.join(state["bundle"], f) for f in BUNDLE_EXECUTED]


def _child(rec, step, script, args, cwd, cenv, runner, timeout, state, paths):
    """Re-check pins, run a child; returns (code, so, se). Raises Refused on a changed pin,
    StepTimeout (after recording UNKNOWN) on timeout."""
    changed = recheck_pins(state["pins"], paths)
    if changed:
        rec.add(step, "REFUSED", detail={"pinned_file_changed": changed})
        raise Refused("pinned file changed: " + ", ".join(changed))
    try:
        return run_py(script, args, cwd, cenv, timeout, runner=runner)
    except subprocess.TimeoutExpired:
        rec.add(step, "UNKNOWN", detail="child killed after %.0f s timeout; effect UNKNOWN" % timeout)
        raise StepTimeout(step)


def _forward(opts, flags, env, connector, runner, rec, tmp, state, acct_approved, approval_sha, clk, run_id):
    try:
        prof = resolve_credentials(env, tmp)
    except Refused as exc:
        rec.add("credentials", "REFUSED", detail=str(exc))
        return EXIT_REFUSED
    if prof is None:
        rec.add("credentials", "BLOCKED", detail="no Snowflake credential in environment")
        return EXIT_BLOCKED
    base = dict(prof["extra"], SZL_EE_RUN_ID=run_id)
    cenv_setup = child_env(env, dict(base, SZL_SF_CONNECTION_NAME=prof["setup_name"]))
    cenv_runtime = child_env(env, dict(base, SZL_SF_CONNECTION_NAME=prof["runtime_name"]))
    state["prof"], state["cenv_setup"], state["cenv_runtime"] = prof, cenv_setup, cenv_runtime
    rec.add("credentials", "PASS", detail={"mode": "A" if prof["extra"] else "B",
                                           "setup_profile": prof["setup_name"], "runtime_profile": prof["runtime_name"]})
    kit, bundle, out = opts["--kit"], opts["--bundle"], rec.out_dir
    manifest = os.path.join(bundle, "MANIFEST.json")
    refusal_code = EXIT_REFUSED

    try:
        c, so, se = _child(rec, "verify", "sf_verify_account_readonly.py",
                           ["--out", os.path.join(out, "verify.json")], kit, cenv_setup, runner,
                           clk.step_timeout(), state, _kit_paths(state, "sf_verify_account_readonly.py"))
    except StepTimeout:
        return EXIT_FAIL                         # read-only step: nothing to reconcile
    except Refused:
        return refusal_code
    rec.add("verify", "PASS" if c == 0 else "FAIL", c, so, se)
    if c != 0:
        return EXIT_BLOCKED if c == 4 else EXIT_FAIL

    ids, problems, locators, users = {}, [], set(), set()
    for label, direct, role, must_not, must_have in (
            ("setup", prof["setup"], SETUP_ROLE, SETUP_MUST_NOT, frozenset()),
            ("runtime", prof["runtime"], RUNTIME_ROLE, RUNTIME_MUST_NOT, RUNTIME_MUST_HAVE)):
        try:
            _, dicts, qid = direct_sql(connector, direct, "identity", run_id,
                                       timeout=min(DIRECT_SQL_TIMEOUT, clk.step_timeout()))
            row = dicts[0] if dicts else {}
        except DeadlineExceeded:
            raise
        except Exception as exc:
            rec.add("identity", "FAIL", detail={"profile": label, "error": type(exc).__name__})
            return EXIT_FAIL
        p, r = check_identity(row, acct_approved, role, must_not, must_have)
        r["query_id"] = qid
        ids[label] = r
        problems += ["%s: %s" % (label, x) for x in p]
        locators.add(r["locator_sha256"])
        users.add(r["user_sha256"])
    if len(locators) != 1:
        problems.append("setup and runtime sessions are in different accounts")
    if len(users) != 2:
        problems.append("setup and runtime sessions are the same user")
    rec.write_json("identity.json", ids)
    if problems:
        rec.add("identity", "REFUSED", detail={"problems": problems})
        return EXIT_REFUSED
    rec.add("identity", "PASS", detail={k: {"primary_role": v["primary_role"], "available_roles": v["available_roles"]}
                                        for k, v in ids.items()})
    locator_sha = ids["runtime"]["locator_sha256"]

    inv = take_inventory(connector, prof["setup"], run_id, lambda: min(DIRECT_SQL_TIMEOUT, clk.step_timeout()))
    rec.write_json("inventory_pre.json", inv)
    if not inv["complete"]:
        rec.add("inventory", "REFUSED", detail={"reason": "inventory incomplete; state not established",
                                                 "errors": inv["errors"]})
        return EXIT_REFUSED
    if inv["existing_pilot_objects"]:
        rec.add("inventory", "REFUSED", detail={"reason": "pilot objects already exist; no overwrite, no retry",
                                                 "existing": inv["existing_pilot_objects"]})
        return EXIT_REFUSED
    if inv["monitor_exact_count"] != 1:
        rec.add("inventory", "REFUSED", detail="resource monitor %s must exist exactly once (owner block D0)" % MONITOR)
        return EXIT_REFUSED
    if inv["warehouse_problems"]:
        rec.add("inventory", "REFUSED", detail={"reason": "owner warehouse %s not in the required state" % WAREHOUSE,
                                                 "problems": inv["warehouse_problems"]})
        return EXIT_REFUSED
    rec.add("inventory", "PASS", detail={"near_matches": inv["near_matches"], "monitor": inv["monitor"],
                                         "warehouse": inv["warehouse"], "roles_visible": inv["roles_visible"]})

    try:
        c, so, se = _child(rec, "dryrun", "sf_deploy_pilot.py", ["--dry-run", "--manifest", manifest],
                           kit, cenv_setup, runner, clk.step_timeout(), state,
                           _kit_paths(state, "sf_deploy_pilot.py"))
    except StepTimeout:
        return EXIT_FAIL                         # dry run never connects
    except Refused:
        return refusal_code
    rec.add("dryrun", "PASS" if c == 0 else "FAIL", c, so, se)
    if c != 0:
        return EXIT_FAIL
    if "--dry-run-only" in flags:
        return EXIT_PARTIAL

    t = clk.step_timeout()                       # DeadlineExceeded here: deploy never starts
    if recheck_pins(state["pins"], _kit_paths(state, "sf_deploy_pilot.py")):
        rec.add("deploy", "REFUSED", detail="pinned kit file changed before deploy")
        return EXIT_REFUSED
    state["deployed"] = True     # from here on, suspend + readback + shutdown verification always run
    rec.state["deployed"] = True
    rec.begin("deploy", detail="sf_deploy_pilot.py --execute (setup profile); timeout %.0f s" % t)
    deploy_json = os.path.join(out, "deploy.json")
    try:
        c, so, se = _child(rec, "deploy", "sf_deploy_pilot.py",
                           ["--execute", "--manifest", manifest, "--approval-file", opts["--approval"],
                            "--out", deploy_json], kit, cenv_setup, runner, t, state,
                           _kit_paths(state, "sf_deploy_pilot.py"))
    except StepTimeout:
        state["uncertain"] = True
        return EXIT_UNCERTAIN
    except Refused:
        return EXIT_FAIL
    ev = _load_json(deploy_json)
    if c == 0:
        checks = (ev or {}).get("post_checks") or []
        if ev is None:
            rec.add("deploy", "UNKNOWN", c, so, se, detail="exit 0 but deploy.json missing or unreadable")
            state["uncertain"] = True
            return EXIT_UNCERTAIN
        bad = [x.get("check") for x in checks if x.get("status") != "PASS"]
        if not checks or bad:
            rec.add("deploy", "FAIL", c, so, se, detail={"post_checks_failed": bad or ["none reported"]})
            return EXIT_FAIL
        rec.add("deploy", "PASS", c, so, se)
    elif c in (3, 4):
        rec.add("deploy", "REFUSED" if c == 3 else "FAIL", c, so, se,
                detail={"changes_begun": (ev or {}).get("changes_begun"), "refusals": (ev or {}).get("refusals")})
        if ev is None or ev.get("changes_begun") is True or (
                "changes_begun" not in ev and ev.get("executed")):
            state["uncertain"] = True
            return EXIT_UNCERTAIN
        return EXIT_REFUSED if c == 3 else EXIT_FAIL
    elif c == 5:
        rec.add("deploy", "FAIL", c, so, se, detail={
            "partial_state": True, "failed_step": (ev or {}).get("failed_step"),
            "executed_count": len((ev or {}).get("executed") or []), "deploy_json_present": ev is not None})
        return EXIT_FAIL
    else:
        rec.add("deploy", "UNKNOWN", c, so, se, detail="unexpected exit code; effect UNKNOWN")
        state["uncertain"] = True
        return EXIT_UNCERTAIN

    t = min(DIRECT_SQL_TIMEOUT, clk.step_timeout())
    rec.begin("resume", detail="runtime profile, secondary role %s" % OPERATOR_ROLE)
    try:
        _, _, qid = direct_sql(connector, prof["runtime"], "resume", run_id, timeout=t)
        rec.add("resume", "PASS", detail="query_id=%s" % qid)
    except Exception as exc:
        rec.add("resume", "UNKNOWN", detail="%s; warehouse state decided by readback" % type(exc).__name__)
        state["uncertain"] = True
        return EXIT_UNCERTAIN

    ienv = dict(cenv_runtime, SZL_EE_INTEGRATION_APPROVAL_REF=approval_sha,
                SZL_EE_SNOWFLAKE_CONNECTION_NAME=prof["runtime_name"],
                SZL_EE_EXPECTED_ACCOUNT_SHA256=locator_sha, SZL_EE_EXPECTED_WAREHOUSE=WAREHOUSE)
    t = clk.step_timeout()
    rec.begin("itests", detail="runtime profile; fixture load (insert-only MERGE as SZL_EE_INGEST) inside i02/i03")
    try:
        c, so, se = _child(rec, "itests", "test_integration_snowflake.py",
                           ["--live-approved", "-v"], bundle, ienv, runner, t,
                           state, _bundle_paths(state))
    except StepTimeout:
        state["uncertain"] = True
        return EXIT_UNCERTAIN
    except Refused:
        return EXIT_FAIL
    res = parse_itests(c, so + "\n" + se)
    rec.write_json("itests.json", res)
    rec.add("itests", res["overall"], c, so, se, detail=res["counts"])
    return {"PASS": EXIT_OK, "NOT_RUN_OR_PARTIAL": EXIT_PARTIAL}.get(res["overall"], EXIT_FAIL)


def _shutdown(opts, state, runner, rec, clock, run_id, forward_code):
    """Own time budget. Returns (verified, partial)."""
    sclk = _Clock(clock, SHUTDOWN_BUDGET_SECONDS)
    connector, prof = state["connector"], state["prof"]

    def t_direct():
        return max(1.0, min(DIRECT_SQL_TIMEOUT, sclk.remaining()))
    rec.begin("suspend", detail="runtime profile, secondary role %s" % OPERATOR_ROLE)
    try:
        _, _, qid = direct_sql(connector, prof["runtime"], "suspend", run_id, timeout=t_direct())
        rec.add("suspend", "PASS", detail="query_id=%s" % qid)
    except StepTimeout:
        state["uncertain"] = True
        rec.add("suspend", "UNKNOWN", detail="suspend still in flight; readback cannot establish final shutdown")
    except Exception as exc:   # already-suspended raises; readback decides
        rec.add("suspend", "ERROR_SEE_READBACK", detail=type(exc).__name__)

    inv = take_inventory(connector, prof["setup"], run_id, t_direct)
    rec.write_json("inventory_post.json", inv)
    winv = take_inventory(connector, prof["runtime"], run_id, t_direct, keys=("inv_warehouses",))
    rec.write_json("warehouse_post_runtime.json", winv)
    wh_state = winv["warehouse_state"] if winv["complete"] else "UNKNOWN"
    setup_wh = inv["warehouse_state"] if not inv["errors"].get("inv_warehouses") else None
    rec.add("readback", "PASS" if (inv["complete"] and winv["complete"]) else "UNKNOWN",
            detail={"warehouse_state_runtime": wh_state, "warehouse_state_setup": setup_wh,
                    "existing_pilot_objects": inv["existing_pilot_objects"]})

    shut_json = os.path.join(rec.out_dir, "shutdown.json")
    rec.begin("shutdown", detail="sf_shutdown_verify.py, runtime profile")
    c, so, se = None, "", ""
    changed = recheck_pins(state["pins"], _kit_paths(state, "sf_shutdown_verify.py"))
    if changed:
        rec.add("shutdown", "FAIL", detail={"pinned_file_changed": changed, "verifier_not_run": True})
    else:
        try:
            c, so, se = run_py("sf_shutdown_verify.py", ["--out", shut_json], opts["--kit"], state["cenv_runtime"],
                               max(1.0, min(STEP_CAP_SECONDS, sclk.remaining())), runner=runner)
        except subprocess.TimeoutExpired:
            rec.add("shutdown", "UNKNOWN", detail="shutdown verifier timed out")
        except Exception as exc:
            rec.add("shutdown", "UNKNOWN", detail=type(exc).__name__)
    sv = _load_json(shut_json) if c is not None else None
    checks = {x.get("id"): x for x in ((sv or {}).get("checks") or []) if isinstance(x, dict)}
    core = {k: (checks.get(k) or {}).get("status", "UNKNOWN") for k in ("W1", "W2", "T1")}
    # bounded() cannot cancel its daemon worker. An earlier timed-out RESUME,
    # SUSPEND or deploy may finish after these readbacks. Preserve uncertainty
    # until an independent reconciliation establishes that no operation remains
    # in flight; a transient SUSPENDED snapshot cannot clear it.
    unresolved = state.get("uncertain", False) or forward_code == EXIT_UNCERTAIN
    verified = (not unresolved and c in (0, 2) and sv is not None and all(v == "PASS" for v in core.values())
                and wh_state == "SUSPENDED" and setup_wh in ("SUSPENDED", None))
    partial = verified and c == 2
    if c is not None:
        rec.add("shutdown", "PASS" if (verified and c == 0) else ("PARTIAL" if verified else "FAIL"), c, so, se,
                detail={"core_checks": core, "runner_readback_warehouse_state": wh_state,
                        "setup_readback_warehouse_state": setup_wh, "shutdown_json_present": sv is not None,
                        "unresolved_operation": unresolved})

    def chk(k):
        return (checks.get(k) or {}).get("detail")
    present = {o["type"]: o for o in inv["existing_pilot_objects"]}
    billable = {
        "run_id": run_id, "utc": now_utc(), "shutdown_verified": verified,
        "forward_exit_code": forward_code, "uncertain_outcome": unresolved,
        "label": "MEASURED by this run's readbacks where a value is present; UNKNOWN otherwise",
        "resources": [
            {"type": "warehouse", "name": WAREHOUSE, "owner": WAREHOUSE_OWNER,
             "state_runtime_readback": wh_state, "state_setup_readback": setup_wh,
             "state_shutdown_verifier": chk("W1"), "auto_resume": chk("W2"),
             "potentially_billing_now": unresolved or wh_state not in ("SUSPENDED", "ABSENT"),
             "unresolved_operation": unresolved,
             "charge": "compute credits while STARTED/RESUMING",
             "if_not_suspended": "the runtime role can only OPERATE; the owner (ACCOUNTADMIN) must suspend it"},
            {"type": "streamlit", "name": APP_FQN,
             "exists": ("streamlit" in present) if not inv["errors"].get("inv_streamlits") else "UNKNOWN",
             "charge": "drives QUERY_WAREHOUSE SZL_EE_WH while a viewer session is open and the warehouse "
                       "runs; billing behaviour after suspension UNKNOWN until verified live"},
            {"type": "stage", "name": STAGE_FQN,
             "exists": ("stage" in present) if not inv["errors"].get("inv_stages") else "UNKNOWN",
             "charge": "storage of staged app files; continues after warehouse suspension"},
            {"type": "database", "name": DATABASE,
             "exists": ("database" in present) if not inv["errors"].get("inv_databases") else "UNKNOWN",
             "charge": "table storage (incl. retention); continues after warehouse suspension"},
            {"type": "other_started_warehouses", "detail": chk("W3")},
            {"type": "tasks_using_pilot_warehouse", "detail": chk("T1")},
            {"type": "resource_monitor", "name": MONITOR, "detail": chk("R1"),
             "note": "a monitor limits warehouse compute only; it is not a hard spending cap"},
        ]}
    rec.write_json("potentially_billable.json", billable)
    rec.add("billable_list", "PASS", detail={"shutdown_verified": verified, "warehouse_state": wh_state})
    return verified, partial


if __name__ == "__main__":
    sys.exit(main())
