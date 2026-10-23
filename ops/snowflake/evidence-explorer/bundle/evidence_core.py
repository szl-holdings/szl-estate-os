"""SZL Evidence Explorer - stdlib core (pilot 1, LOCAL draft).

SYNTHETIC DEMONSTRATION DATA ONLY in pilot 1. This module never opens a
network connection, never reads credentials and never executes SQL itself.
It provides:
  * closed-schema, fail-closed row validation (strict enums, bounded lengths,
    UTC-only timestamps, immutable revisions, explicit missing values);
  * content-digest verification;
  * duplicate-safe, append-only batch ingestion into a LocalStore that is a
    reference model of the Snowflake tables (no delete / update / reset);
  * exclusion enforcement at ingestion and display;
  * rejected-row retention (reason code + digest, never raw values);
  * parameterized query builders with bounded LIMIT for the Streamlit app;
  * presentation helpers with truthful EMPTY / ERROR / NOT MEASURED states.
Hashes support content integrity only - not authorship, signatures or truth.
"""
import datetime as _dt
import hashlib
import json
import re
import threading
from collections import namedtuple

SYNTHETIC_LABEL = ("SYNTHETIC DEMONSTRATION DATA \u2014 NOT PRODUCTION OR MODEL "
                   "QUALIFICATION.")

# ---------------------------------------------------------------- enums
PROVIDERS = ("GITHUB", "HUGGINGFACE", "RUNTIME")
VISIBILITY_CLASSES = ("PUBLIC", "PRIVATE", "RESTRICTED", "UNKNOWN")
DISPOSITIONS = ("KEEP_CANONICAL", "INGEST_APPROVED_METADATA", "PILOT_ADAPTER",
                "MIGRATE_AFTER_REVIEW", "EXCLUDED", "BLOCKED", "UNKNOWN")
EVIDENCE_CLASSES = ("MEASURED", "REPORTED", "UNKNOWN")
OBSERVATION_TYPES = ("ILLUSTRATIVE_SCORE", "TEST_RUN_SUMMARY", "CARD_FIELD",
                     "RUNTIME_PROBE", "CHECKSUM_RECORD")
VALUE_STATES = ("PRESENT", "MISSING", "NOT_MEASURED")
ALLOWED_USES = ("METADATA_DISPLAY", "METADATA_INTERNAL", "NONE", "UNKNOWN")
REDISTRIBUTION_STATUSES = ("ALLOWED", "RESTRICTED", "PROHIBITED", "UNKNOWN")
DIGEST_ALGORITHMS = ("sha256",)
BATCH_STATUSES = ("COMPLETED", "COMPLETED_WITH_REJECTIONS", "FAILED")
EXCLUSION_REASONS = ("OWNER_EXCLUSION", "RIGHTS_DENIED", "PRIVATE_SOURCE",
                     "SECRET_RISK", "OUT_OF_SCOPE")
EXCLUSION_SCOPES = ("ALL", "INGESTION", "DISPLAY")
REASON_CODES = ("NOT_A_MAPPING", "SECRET_FIELD", "SECRET_VALUE", "UNKNOWN_FIELD",
                "MISSING_FIELD", "TYPE_VIOLATION", "ENUM_VIOLATION",
                "MALFORMED_FIELD", "MALFORMED_TIMESTAMP", "FUTURE_TIMESTAMP",
                "MALFORMED_REVISION", "SYNTHETIC_LABEL_REQUIRED",
                "INCONSISTENT_FIELDS", "EXCLUDED", "ORPHAN_REFERENCE",
                "CONTENT_DIGEST_MISMATCH", "DIGEST_UNVERIFIABLE", "RIGHTS_DENIED",
                "CONFLICTING_DUPLICATE_ID")

# ---------------------------------------------------------------- bounds
MAX_ROWS_PER_BATCH = 500
MAX_BATCH_BYTES = 262144
MAX_QUERY_LIMIT = 200
DEFAULT_QUERY_LIMIT = 50
STALE_AFTER_DAYS = 90

# ---------------------------------------------------------------- grammar
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
LOCATOR_RE = re.compile(
    r"(mock://(github|huggingface|runtime)/[a-z0-9][A-Za-z0-9._/-]{0,198}"
    r"|https://(github\.com|huggingface\.co)/[A-Za-z0-9][A-Za-z0-9._/-]{0,198})")
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}")
REVISION_RE = re.compile(r"(git-sha1:[0-9a-f]{40}|git-sha256:[0-9a-f]{64}"
                         r"|hf-commit:[0-9a-f]{40}|runtime-build:[0-9a-f]{16})")
REVISION_PREFIX_BY_PROVIDER = {"GITHUB": ("git-sha1:", "git-sha256:"),
                               "HUGGINGFACE": ("hf-commit:",),
                               "RUNTIME": ("runtime-build:",)}
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
TS_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?Z")
VALUE_RE = re.compile(r"[A-Za-z0-9 .,:;=+_/%()-]{1,64}")
SOURCE_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,199}")
SECRET_NAME_RE = re.compile(
    r"(secret|token|passw|api[_-]?key|private[_-]?key|credential|bearer|cookie"
    r"|session[_-]?id|auth)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{8,}|gho_[A-Za-z0-9]{8,}|github_pat_|hf_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.|xox[baprs]-)")
SCHEMA_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\.[A-Z][A-Z0-9_]{0,63}")

_SYN = ("is_synthetic", "synthetic")
_LAB = ("data_label", "label")
TABLE_SPECS = {
    "ASSETS": (("asset_id", "id"), ("provider", "enum", PROVIDERS),
               ("canonical_locator", "locator"), ("owner_reference", "ref"),
               ("visibility_class", "enum", VISIBILITY_CLASSES),
               ("disposition", "enum", DISPOSITIONS), _SYN, _LAB),
    "REVISIONS": (("revision_id", "id"), ("asset_id", "id"),
                  ("immutable_source_revision", "revision"),
                  ("observed_at_utc", "ts"), ("source_locator", "locator"),
                  ("content_digest_algorithm", "enum", DIGEST_ALGORITHMS),
                  ("content_digest", "digest"), _SYN, _LAB),
    "OBSERVATIONS": (("observation_id", "id"), ("revision_id", "id"),
                     ("evidence_class", "enum", EVIDENCE_CLASSES),
                     ("observation_type", "enum", OBSERVATION_TYPES),
                     ("observed_at_utc", "ts"), ("source_locator", "locator"),
                     ("value_state", "enum", VALUE_STATES),
                     ("summarized_value", "value_or_null"), _SYN, _LAB),
    "RIGHTS_RECORDS": (("rights_record_id", "id"), ("source_locator", "locator"),
                       ("license_reference", "ref"),
                       ("allowed_use", "enum", ALLOWED_USES),
                       ("redistribution_status", "enum", REDISTRIBUTION_STATUSES),
                       ("training_allowed", "bool"),
                       ("training_evidence_ref", "ref_or_null"),
                       ("reviewed_at_utc", "ts"), _SYN, _LAB),
    "EXCLUSIONS": (("source_identifier", "source_identifier"),
                   ("exclusion_reason", "enum", EXCLUSION_REASONS),
                   ("effective_at_utc", "ts"),
                   ("scope", "enum", EXCLUSION_SCOPES)),
}
# Processing order inside one batch: governance first, then parents.
TABLE_ORDER = ("EXCLUSIONS", "RIGHTS_RECORDS", "ASSETS", "REVISIONS", "OBSERVATIONS")
KEY_FIELDS = {"ASSETS": ("asset_id",), "REVISIONS": ("revision_id",),
              "OBSERVATIONS": ("observation_id",),
              "RIGHTS_RECORDS": ("rights_record_id",),
              "EXCLUSIONS": ("source_identifier", "scope")}
EXCLUDABLE_FIELDS = ("asset_id", "revision_id", "observation_id",
                     "canonical_locator", "source_locator",
                     "immutable_source_revision", "content_digest")


class Rejection(Exception):
    def __init__(self, reason, field=None):
        if reason not in REASON_CODES:
            raise ValueError("unregistered reason code")
        super().__init__(reason)
        self.reason = reason
        self.field = field


class QueryError(ValueError):
    """Raised when a query request is outside the allowlisted grammar."""


# ---------------------------------------------------------------- helpers
def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def parse_utc(value):
    """Strict 'YYYY-MM-DDTHH:MM:SS[.ffffff]Z' -> aware datetime, else Rejection."""
    if type(value) is not str:
        raise Rejection("TYPE_VIOLATION")
    m = TS_RE.fullmatch(value)
    if m is None:
        raise Rejection("MALFORMED_TIMESTAMP")
    frac = m.group(7)
    micro = int((frac[1:] + "000000")[:6]) if frac else 0
    try:
        out = _dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                           int(m.group(4)), int(m.group(5)), int(m.group(6)),
                           micro, tzinfo=_dt.timezone.utc)
    except ValueError:
        raise Rejection("MALFORMED_TIMESTAMP")
    if out.year < 2000:
        raise Rejection("MALFORMED_TIMESTAMP")
    return out


def _check_field(name, kind, spec, value, as_of):
    if kind in ("id", "locator", "ref", "revision", "digest", "source_identifier", "label"):
        if type(value) is not str:
            raise Rejection("TYPE_VIOLATION", name)
    if kind == "id" and ID_RE.fullmatch(value) is None:
        raise Rejection("MALFORMED_FIELD", name)
    elif kind == "locator":
        if LOCATOR_RE.fullmatch(value) is None or ".." in value or "//" in value[8:]:
            raise Rejection("MALFORMED_FIELD", name)
    elif kind == "ref" and REF_RE.fullmatch(value) is None:
        raise Rejection("MALFORMED_FIELD", name)
    elif kind == "revision" and REVISION_RE.fullmatch(value) is None:
        raise Rejection("MALFORMED_REVISION", name)
    elif kind == "digest" and DIGEST_RE.fullmatch(value) is None:
        raise Rejection("MALFORMED_FIELD", name)
    elif kind == "source_identifier" and SOURCE_IDENTIFIER_RE.fullmatch(value) is None:
        raise Rejection("MALFORMED_FIELD", name)
    elif kind == "enum":
        if type(value) is not str:
            raise Rejection("TYPE_VIOLATION", name)
        if value not in spec:
            raise Rejection("ENUM_VIOLATION", name)
    elif kind == "ts":
        try:
            when = parse_utc(value)
        except Rejection as exc:
            raise Rejection(exc.reason, name)
        if when > as_of:
            raise Rejection("FUTURE_TIMESTAMP", name)
    elif kind in ("bool", "synthetic"):
        if type(value) is not bool:
            raise Rejection("TYPE_VIOLATION", name)
        if kind == "synthetic" and value is not True:
            raise Rejection("SYNTHETIC_LABEL_REQUIRED", name)
    elif kind == "label":
        if value != SYNTHETIC_LABEL:
            raise Rejection("SYNTHETIC_LABEL_REQUIRED", name)
    elif kind in ("value_or_null", "ref_or_null"):
        if value is not None:
            if type(value) is not str:
                raise Rejection("TYPE_VIOLATION", name)
            pattern = VALUE_RE if kind == "value_or_null" else REF_RE
            if pattern.fullmatch(value) is None:
                raise Rejection("MALFORMED_FIELD", name)


def _iter_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_strings(k)
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


def validate_row(table, row, as_of):
    """Closed-schema, row-local validation. Returns None or raises Rejection."""
    if table not in TABLE_SPECS:
        raise QueryError("unknown table")
    if type(row) is not dict:
        raise Rejection("NOT_A_MAPPING")
    for key in row:
        if type(key) is not str or SECRET_NAME_RE.search(key):
            raise Rejection("SECRET_FIELD", None)
    for text in _iter_strings(row):
        if SECRET_VALUE_RE.search(text):
            raise Rejection("SECRET_VALUE", None)
    spec = TABLE_SPECS[table]
    names = tuple(f[0] for f in spec)
    for key in row:
        if key not in names:
            raise Rejection("UNKNOWN_FIELD", key)
    for name in names:
        if name not in row:
            raise Rejection("MISSING_FIELD", name)
    for field in spec:
        name, kind = field[0], field[1]
        _check_field(name, kind, field[2] if len(field) > 2 else None, row[name], as_of)
    if table == "OBSERVATIONS":
        present = row["value_state"] == "PRESENT"
        if present != (row["summarized_value"] is not None):
            raise Rejection("INCONSISTENT_FIELDS", "summarized_value")
    if table == "RIGHTS_RECORDS":
        if row["training_allowed"] is True and row["training_evidence_ref"] is None:
            raise Rejection("INCONSISTENT_FIELDS", "training_allowed")
    return None


# ---------------------------------------------------------------- store
class LocalStore:
    """Append-only reference model of the pilot tables. No delete/update API."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tables = {t: [] for t in TABLE_SPECS}
        self._batches = []
        self._rejected = []

    def rows(self, table):
        if table == "INGESTION_BATCHES":
            return [dict(r) for r in self._batches]
        if table == "REJECTED_ROWS":
            return [dict(r) for r in self._rejected]
        return [dict(r) for r in self._tables[table]]

    def counts(self):
        out = {t: len(v) for t, v in self._tables.items()}
        out["INGESTION_BATCHES"] = len(self._batches)
        out["REJECTED_ROWS"] = len(self._rejected)
        return out


def _key(table, row):
    return tuple(row[k] for k in KEY_FIELDS[table])


def _excluded(row, exclusions, scopes):
    idents = set()
    for f in EXCLUDABLE_FIELDS:
        v = row.get(f)
        if type(v) is str:
            idents.add(v)
            if ":" in v and not v.startswith(("mock://", "https://")):
                idents.add(v.split(":", 1)[1])
    for ex in exclusions:
        if ex["scope"] in scopes and ex["source_identifier"] in idents:
            return True
    return False


def _bounded_summary(reason_counts, bound=256):
    """Value-free 'REASON=n;...' summary, cut on a token boundary within bound."""
    out = ""
    items = sorted(reason_counts.items())
    for i, kv in enumerate(items):
        token = ("" if not out else ";") + "%s=%d" % kv
        if len(out) + len(token) > bound - 12:
            return out + ";+%d_MORE" % (len(items) - i)
        out += token
    return out or None


def manifest_digest(payload):
    return sha256_hex(canonical_bytes(payload))


def ingest_batch(store, payload, as_of, local_content=None):
    """Duplicate-safe ingestion. Idempotent by input_manifest_digest.

    payload = {"source_revision": str, "tables": {TABLE: [row, ...]}}
    local_content = {revision_id: bytes} used ONLY to verify content_digest;
    it is never stored. Returns a result dict; never deletes or rewrites.
    """
    as_of_dt = parse_utc(as_of)
    local_content = {} if local_content is None else local_content
    with store._lock:
        try:
            raw = canonical_bytes(payload)
        except (TypeError, ValueError):
            raw = None
        digest = sha256_hex(raw) if raw is not None else None
        if digest is not None:
            for b in store._batches:
                if b["input_manifest_digest"] == digest:
                    return {"duplicate": True, "batch": dict(b), "accepted": 0,
                            "rejected": 0, "skipped_duplicates": 0}
        failure = None
        if raw is None:
            failure = "MALFORMED_BATCH"
        elif len(raw) > MAX_BATCH_BYTES:
            failure = "REQUEST_TOO_LARGE"
        elif (type(payload) is not dict or set(payload) != {"source_revision", "tables"}
              or type(payload["tables"]) is not dict
              or not set(payload["tables"]) <= set(TABLE_SPECS)
              or type(payload["source_revision"]) is not str
              or REF_RE.fullmatch(payload["source_revision"]) is None
              or any(type(v) is not list for v in payload["tables"].values())):
            failure = "MALFORMED_BATCH"
        elif sum(len(v) for v in payload["tables"].values()) > MAX_ROWS_PER_BATCH:
            failure = "TOO_MANY_ROWS"
        batch_id = "batch-" + (digest[:24] if digest else
                               sha256_hex(repr(as_of).encode())[:24])
        stamp = as_of
        if failure is not None:
            rec = {"batch_id": batch_id, "input_manifest_digest": digest,
                   "source_revision": None, "started_at_utc": stamp,
                   "finished_at_utc": stamp, "status": "FAILED",
                   "accepted_count": 0, "rejected_count": 0,
                   "error_summary": failure}
            store._batches.append(rec)
            return {"duplicate": False, "batch": dict(rec), "accepted": 0,
                    "rejected": 0, "skipped_duplicates": 0}

        staged = {t: [] for t in TABLE_SPECS}
        rejected = []
        skipped = 0
        reason_counts = {}

        def existing(table):
            return store._tables[table] + staged[table]

        for table in TABLE_ORDER:
            for ordinal, row in enumerate(payload["tables"].get(table, [])):
                try:
                    validate_row(table, row, as_of_dt)
                    exclusions = existing("EXCLUSIONS")
                    if table != "EXCLUSIONS" and _excluded(row, exclusions,
                                                           ("ALL", "INGESTION")):
                        raise Rejection("EXCLUDED")
                    if table == "REVISIONS":
                        assets = [a for a in existing("ASSETS")
                                  if a["asset_id"] == row["asset_id"]]
                        if not assets:
                            raise Rejection("ORPHAN_REFERENCE", "asset_id")
                        prefixes = REVISION_PREFIX_BY_PROVIDER[assets[0]["provider"]]
                        if not row["immutable_source_revision"].startswith(prefixes):
                            raise Rejection("MALFORMED_REVISION",
                                            "immutable_source_revision")
                        content = local_content.get(row["revision_id"])
                        if type(content) is not bytes:
                            raise Rejection("DIGEST_UNVERIFIABLE", "content_digest")
                        if sha256_hex(content) != row["content_digest"]:
                            raise Rejection("CONTENT_DIGEST_MISMATCH", "content_digest")
                    if table == "OBSERVATIONS":
                        revs = [r for r in existing("REVISIONS")
                                if r["revision_id"] == row["revision_id"]]
                        if not revs:
                            raise Rejection("ORPHAN_REFERENCE", "revision_id")
                        asset = [a for a in existing("ASSETS")
                                 if a["asset_id"] == revs[0]["asset_id"]][0]
                        rights = latest_rights(existing("RIGHTS_RECORDS"),
                                               asset["canonical_locator"])
                        if rights is not None and rights["allowed_use"] == "NONE":
                            raise Rejection("RIGHTS_DENIED")
                    key = _key(table, row)
                    prior = [r for r in existing(table) if _key(table, r) == key]
                    if prior:
                        if canonical_bytes(prior[0]) == canonical_bytes(row):
                            skipped += 1
                            continue
                        raise Rejection("CONFLICTING_DUPLICATE_ID",
                                        KEY_FIELDS[table][0])
                    staged[table].append(dict(row))
                except Rejection as exc:
                    secret = exc.reason in ("SECRET_FIELD", "SECRET_VALUE")
                    try:
                        row_digest = None if secret else sha256_hex(canonical_bytes(row))
                    except (TypeError, ValueError):
                        row_digest = None
                    rejected.append({
                        "rejected_row_id": "rej-" + sha256_hex(
                            ("%s|%s|%d" % (batch_id, table, ordinal)).encode())[:24],
                        "batch_id": batch_id, "source_table": table,
                        "row_ordinal": ordinal, "reason_code": exc.reason,
                        "field_name": exc.field, "row_digest": row_digest,
                        "rejected_at_utc": stamp})
                    reason_counts[exc.reason] = reason_counts.get(exc.reason, 0) + 1
        accepted = sum(len(v) for v in staged.values())
        summary = _bounded_summary(reason_counts)
        rec = {"batch_id": batch_id, "input_manifest_digest": digest,
               "source_revision": payload["source_revision"],
               "started_at_utc": stamp, "finished_at_utc": stamp,
               "status": "COMPLETED_WITH_REJECTIONS" if rejected else "COMPLETED",
               "accepted_count": accepted, "rejected_count": len(rejected),
               "error_summary": summary}
        for t in TABLE_SPECS:
            store._tables[t].extend(staged[t])
        store._rejected.extend(rejected)
        store._batches.append(rec)
        return {"duplicate": False, "batch": dict(rec), "accepted": accepted,
                "rejected": len(rejected), "skipped_duplicates": skipped}


# ---------------------------------------------------------------- presentation
def latest_rights(rights_rows, locator):
    match = [r for r in rights_rows if r["source_locator"] == locator]
    if not match:
        return None
    return sorted(match, key=lambda r: (parse_utc(r["reviewed_at_utc"]),
                                        r["rights_record_id"]))[-1]


def freshness(observed_at_utc, as_of):
    when = parse_utc(observed_at_utc)
    ref = parse_utc(as_of)
    return "STALE" if (ref - when).days > STALE_AFTER_DAYS else "CURRENT"


def display_value(obs, rights):
    """Descriptive display only; never a promotion decision."""
    if obs["value_state"] != "PRESENT":
        return obs["value_state"], obs["value_state"]
    if rights is None or rights["allowed_use"] == "UNKNOWN":
        return "WITHHELD: RIGHTS_UNKNOWN", "RIGHTS_UNKNOWN"
    if (rights["allowed_use"] != "METADATA_DISPLAY"
            or rights["redistribution_status"] == "PROHIBITED"):
        return "WITHHELD: RIGHTS_RESTRICTED", "RIGHTS_RESTRICTED"
    return obs["summarized_value"], "SHOWN"


def present_observation(obs, rights, as_of):
    value, state = display_value(obs, rights)
    return {"observation_id": obs["observation_id"],
            "revision_id": obs["revision_id"],
            "evidence_class": obs["evidence_class"],
            "observation_type": obs["observation_type"],
            "observed_at_utc": obs["observed_at_utc"],
            "freshness": freshness(obs["observed_at_utc"], as_of),
            "source_locator": obs["source_locator"],
            "display_value": value, "display_state": state,
            "is_synthetic": obs["is_synthetic"], "data_label": obs["data_label"]}


def apply_display_exclusions(rows, exclusions):
    kept = [r for r in rows if not _excluded(r, exclusions, ("ALL", "DISPLAY"))]
    return kept, len(rows) - len(kept)


def classify_gaps(presented):
    gaps = []
    for p in presented:
        reasons = []
        if p["display_state"] in ("MISSING", "NOT_MEASURED", "RIGHTS_RESTRICTED",
                                  "RIGHTS_UNKNOWN"):
            reasons.append(p["display_state"])
        if p["freshness"] == "STALE":
            reasons.append("STALE")
        if reasons:
            g = dict(p)
            g["gap_reasons"] = ",".join(reasons)
            gaps.append(g)
    return gaps


def inventory_gaps(inventory, presented):
    """Asset-level gaps: no accepted revision, or latest revision unobserved."""
    observed = {p["revision_id"] for p in presented}
    out = []
    for a in inventory:
        if a.get("revision_id") is None:
            out.append({"asset_id": a["asset_id"], "gap_reasons": "NO_ACCEPTED_REVISION"})
        elif a["revision_id"] not in observed:
            out.append({"asset_id": a["asset_id"], "revision_id": a["revision_id"],
                        "gap_reasons": "NO_ACCEPTED_OBSERVATIONS"})
    return out


def compare_revisions(obs_a, obs_b):
    """Pairs observations of two revisions by observation_type. Descriptive."""
    a = {o["observation_type"]: o for o in obs_a}
    b = {o["observation_type"]: o for o in obs_b}
    out = []
    for t in sorted(set(a) | set(b)):
        va = a[t]["display_value"] if t in a else None
        vb = b[t]["display_value"] if t in b else None
        if t not in b:
            change = "ONLY_IN_A"
        elif t not in a:
            change = "ONLY_IN_B"
        elif a[t]["display_state"] != "SHOWN" or b[t]["display_state"] != "SHOWN":
            change = "NOT_COMPARABLE"
        elif va == vb:
            change = "SAME"
        else:
            change = "DIFFERENT"
        out.append({"observation_type": t, "revision_a_value": va,
                    "revision_b_value": vb, "change": change,
                    "interpretation": "DESCRIPTIVE_ONLY_NOT_A_PROMOTION_DECISION"})
    return out


ScreenState = namedtuple("ScreenState", "state rows message truncated")


def screen_state(rows, error=None, limit=None):
    """Truthful state: ERROR shows no rows; EMPTY never pretends to be OK."""
    if error is not None:
        return ScreenState("ERROR", [], "LIVE QUERY FAILED: %s. No data is shown; "
                           "nothing is cached or simulated." % error, False)
    if not rows:
        return ScreenState("EMPTY", [], "The live query returned no rows. Absence "
                           "here is not evidence that upstream evidence is absent.",
                           False)
    truncated = limit is not None and len(rows) >= limit
    msg = ("Showing %d rows (result limit reached; more may exist)." % len(rows)
           if truncated else "Showing %d rows." % len(rows))
    return ScreenState("OK", list(rows), msg, truncated)


def cost_status(measurement=None):
    """Cost/run screen. Only a real, sanitized measurement may be displayed."""
    if measurement is None:
        return {"state": "NOT_MEASURED",
                "message": "Cost and run information: not measured. No warehouse "
                           "credits, runtime or query cost have been measured for "
                           "this app; no estimate is shown in their place."}
    required = {"source", "measured_at_utc", "credits_used", "query_count"}
    if (type(measurement) is not dict or set(measurement) != required
            or measurement["source"] != "SNOWFLAKE_ACCOUNT_USAGE"):
        return {"state": "NOT_MEASURED",
                "message": "Cost and run information: not measured (measurement "
                           "record rejected as incomplete or unsourced)."}
    return {"state": "MEASURED", "message": "Measured from account usage.",
            "record": dict(measurement)}


# ---------------------------------------------------------------- queries
QuerySpec = namedtuple("QuerySpec", "name sql params limit")
DEFAULT_DATA_SCHEMA = "SZL_EE_DB.EE_DATA"


def _limit(limit):
    if type(limit) is not int or limit < 1 or limit > MAX_QUERY_LIMIT:
        raise QueryError("limit must be an int in 1..%d" % MAX_QUERY_LIMIT)
    return limit


def _schema(schema):
    if type(schema) is not str or SCHEMA_NAME_RE.fullmatch(schema) is None:
        raise QueryError("schema must be DB.SCHEMA in upper-case identifiers")
    return schema


def _id_param(value, name):
    if type(value) is not str or ID_RE.fullmatch(value) is None:
        raise QueryError("%s is not a valid identifier" % name)
    return value


def _spec(name, body, params, limit, schema):
    s = _schema(schema)
    n = _limit(limit)
    sql = "/* q:%s */ %s LIMIT %d" % (name, body.replace("{S}", s), n)
    return QuerySpec(name, sql, tuple(params), n)


def q_asset_inventory(provider=None, limit=DEFAULT_QUERY_LIMIT, schema=DEFAULT_DATA_SCHEMA):
    params = []
    where = ""
    if provider is not None:
        if provider not in PROVIDERS:
            raise QueryError("provider not in enum")
        where = "WHERE a.PROVIDER = ? "
        params.append(provider)
    body = ("SELECT a.ASSET_ID, a.PROVIDER, a.CANONICAL_LOCATOR, a.DISPOSITION, "
            "r.REVISION_ID, r.IMMUTABLE_SOURCE_REVISION, r.OBSERVED_AT_UTC, "
            "(SELECT COUNT(*) FROM {S}.REVISIONS c WHERE c.ASSET_ID = a.ASSET_ID) "
            "AS REVISION_COUNT, a.IS_SYNTHETIC, a.DATA_LABEL "
            "FROM {S}.ASSETS a LEFT JOIN {S}.REVISIONS r ON r.ASSET_ID = a.ASSET_ID "
            + where +
            "QUALIFY ROW_NUMBER() OVER (PARTITION BY a.ASSET_ID ORDER BY "
            "r.OBSERVED_AT_UTC DESC NULLS LAST, r.REVISION_ID) = 1 "
            "ORDER BY a.ASSET_ID")
    return _spec("asset_inventory", body, params, limit, schema)


def q_asset_revisions(asset_id, limit=DEFAULT_QUERY_LIMIT, schema=DEFAULT_DATA_SCHEMA):
    body = ("SELECT r.REVISION_ID, r.ASSET_ID, r.IMMUTABLE_SOURCE_REVISION, "
            "r.OBSERVED_AT_UTC, r.SOURCE_LOCATOR, r.CONTENT_DIGEST_ALGORITHM, "
            "r.CONTENT_DIGEST FROM {S}.REVISIONS r WHERE r.ASSET_ID = ? "
            "ORDER BY r.OBSERVED_AT_UTC, r.REVISION_ID")
    return _spec("asset_revisions", body, [_id_param(asset_id, "asset_id")], limit, schema)


_OBS_COLS = ("o.OBSERVATION_ID, o.REVISION_ID, o.EVIDENCE_CLASS, o.OBSERVATION_TYPE, "
             "o.OBSERVED_AT_UTC, o.SOURCE_LOCATOR, o.VALUE_STATE, o.SUMMARIZED_VALUE, "
             "o.IS_SYNTHETIC, o.DATA_LABEL, a.ASSET_ID, a.CANONICAL_LOCATOR, "
             "rr.ALLOWED_USE, rr.REDISTRIBUTION_STATUS, rr.RIGHTS_RECORD_ID, "
             "rr.REVIEWED_AT_UTC AS RIGHTS_REVIEWED_AT_UTC")
_OBS_FROM = ("FROM {S}.OBSERVATIONS o JOIN {S}.REVISIONS r ON r.REVISION_ID = o.REVISION_ID "
             "JOIN {S}.ASSETS a ON a.ASSET_ID = r.ASSET_ID "
             "LEFT JOIN (SELECT * FROM {S}.RIGHTS_RECORDS QUALIFY ROW_NUMBER() OVER "
             "(PARTITION BY SOURCE_LOCATOR ORDER BY REVIEWED_AT_UTC DESC, "
             "RIGHTS_RECORD_ID DESC) = 1) rr ON rr.SOURCE_LOCATOR = a.CANONICAL_LOCATOR ")


def q_evidence_detail(revision_id, limit=DEFAULT_QUERY_LIMIT, schema=DEFAULT_DATA_SCHEMA):
    body = ("SELECT " + _OBS_COLS + " " + _OBS_FROM +
            "WHERE o.REVISION_ID = ? ORDER BY o.OBSERVATION_TYPE, o.OBSERVATION_ID")
    return _spec("evidence_detail", body, [_id_param(revision_id, "revision_id")],
                 limit, schema)


def q_revision_comparison(revision_a, revision_b, limit=DEFAULT_QUERY_LIMIT,
                          schema=DEFAULT_DATA_SCHEMA):
    a = _id_param(revision_a, "revision_a")
    b = _id_param(revision_b, "revision_b")
    if a == b:
        raise QueryError("comparison needs two different revisions")
    body = ("SELECT " + _OBS_COLS + " " + _OBS_FROM +
            "WHERE o.REVISION_ID IN (?, ?) ORDER BY o.REVISION_ID, o.OBSERVATION_TYPE, "
            "o.OBSERVATION_ID")
    return _spec("revision_comparison", body, [a, b], limit, schema)


def q_all_observations(limit=MAX_QUERY_LIMIT, schema=DEFAULT_DATA_SCHEMA):
    body = ("SELECT " + _OBS_COLS + " " + _OBS_FROM +
            "ORDER BY a.ASSET_ID, o.OBSERVATION_ID")
    return _spec("all_observations", body, [], limit, schema)


def q_ingestion_batches(limit=DEFAULT_QUERY_LIMIT, schema=DEFAULT_DATA_SCHEMA):
    body = ("SELECT BATCH_ID, INPUT_MANIFEST_DIGEST, SOURCE_REVISION, STARTED_AT_UTC, "
            "FINISHED_AT_UTC, STATUS, ACCEPTED_COUNT, REJECTED_COUNT, ERROR_SUMMARY "
            "FROM {S}.INGESTION_BATCHES ORDER BY STARTED_AT_UTC, BATCH_ID")
    return _spec("ingestion_batches", body, [], limit, schema)


def q_rejected_rows(limit=DEFAULT_QUERY_LIMIT, schema=DEFAULT_DATA_SCHEMA):
    body = ("SELECT REJECTED_ROW_ID, BATCH_ID, SOURCE_TABLE, ROW_ORDINAL, REASON_CODE, "
            "FIELD_NAME, ROW_DIGEST, REJECTED_AT_UTC FROM {S}.REJECTED_ROWS "
            "ORDER BY BATCH_ID, SOURCE_TABLE, ROW_ORDINAL")
    return _spec("rejected_rows", body, [], limit, schema)


def q_exclusions(limit=MAX_QUERY_LIMIT, schema=DEFAULT_DATA_SCHEMA):
    body = ("SELECT SOURCE_IDENTIFIER, EXCLUSION_REASON, EFFECTIVE_AT_UTC, SCOPE "
            "FROM {S}.EXCLUSIONS ORDER BY SOURCE_IDENTIFIER, SCOPE")
    return _spec("exclusions", body, [], limit, schema)


def build_merge(table, row, schema=DEFAULT_DATA_SCHEMA):
    """Insert-if-absent MERGE with bind variables only. Never UPDATE/DELETE.

    Dedup is enforced by this ON clause plus ingest_batch's pre-check; Snowflake
    does not enforce PRIMARY KEY/UNIQUE on standard tables. Concurrent writers
    must serialize per batch (single-writer pilot)."""
    if table not in TABLE_SPECS and table not in ("INGESTION_BATCHES", "REJECTED_ROWS"):
        raise QueryError("unknown table")
    if table == "INGESTION_BATCHES":
        cols = ("batch_id", "input_manifest_digest", "source_revision",
                "started_at_utc", "finished_at_utc", "status", "accepted_count",
                "rejected_count", "error_summary")
        keys = ("input_manifest_digest",)
    elif table == "REJECTED_ROWS":
        cols = ("rejected_row_id", "batch_id", "source_table", "row_ordinal",
                "reason_code", "field_name", "row_digest", "rejected_at_utc")
        keys = ("rejected_row_id",)
    else:
        cols = tuple(f[0] for f in TABLE_SPECS[table])
        keys = KEY_FIELDS[table]
    if type(row) is not dict or set(row) != set(cols):
        raise QueryError("row columns do not match the table contract")
    s = _schema(schema)
    up = [c.upper() for c in cols]
    src = ", ".join("? AS %s" % c for c in up)
    on = " AND ".join("t.%s = s.%s" % (k.upper(), k.upper()) for k in keys)
    sql = ("/* q:merge_%s */ MERGE INTO %s.%s t USING (SELECT %s) s ON %s "
           "WHEN NOT MATCHED THEN INSERT (%s) VALUES (%s)"
           % (table.lower(), s, table, src, on, ", ".join(up),
              ", ".join("s.%s" % c for c in up)))
    return QuerySpec("merge_" + table.lower(), sql, tuple(row[c] for c in cols), None)


# ---------------------------------------------------------------- local reference execution
def _upper(d):
    return {k.upper(): v for k, v in d.items()}


def _obs_join(store):
    revs = {r["revision_id"]: r for r in store.rows("REVISIONS")}
    assets = {a["asset_id"]: a for a in store.rows("ASSETS")}
    rights = store.rows("RIGHTS_RECORDS")
    out = []
    for o in store.rows("OBSERVATIONS"):
        a = assets[revs[o["revision_id"]]["asset_id"]]
        rr = latest_rights(rights, a["canonical_locator"]) or {}
        d = dict(o)
        d.update({"asset_id": a["asset_id"], "canonical_locator": a["canonical_locator"],
                  "allowed_use": rr.get("allowed_use"),
                  "redistribution_status": rr.get("redistribution_status"),
                  "rights_record_id": rr.get("rights_record_id"),
                  "rights_reviewed_at_utc": rr.get("reviewed_at_utc")})
        out.append(d)
    return out


def local_execute(store, spec):
    """Reference semantics of each named query over a LocalStore (tests/stub)."""
    p = spec.params
    if spec.name == "asset_inventory":
        revs = store.rows("REVISIONS")
        out = []
        for a in sorted(store.rows("ASSETS"), key=lambda x: x["asset_id"]):
            if p and a["provider"] != p[0]:
                continue
            mine = [r for r in revs if r["asset_id"] == a["asset_id"]]
            last = {}
            if mine:
                newest = max(parse_utc(r["observed_at_utc"]) for r in mine)
                # SQL: ORDER BY OBSERVED_AT_UTC DESC NULLS LAST, REVISION_ID -> smallest id
                last = min((r for r in mine if parse_utc(r["observed_at_utc"]) == newest),
                           key=lambda r: r["revision_id"])
            out.append({"asset_id": a["asset_id"], "provider": a["provider"],
                        "canonical_locator": a["canonical_locator"],
                        "disposition": a["disposition"],
                        "revision_id": last.get("revision_id"),
                        "immutable_source_revision": last.get("immutable_source_revision"),
                        "observed_at_utc": last.get("observed_at_utc"),
                        "revision_count": len(mine), "is_synthetic": a["is_synthetic"],
                        "data_label": a["data_label"]})
    elif spec.name == "asset_revisions":
        out = sorted((r for r in store.rows("REVISIONS") if r["asset_id"] == p[0]),
                     key=lambda r: (parse_utc(r["observed_at_utc"]), r["revision_id"]))
        out = [{k: v for k, v in r.items() if k not in ("is_synthetic", "data_label")}
               for r in out]
    elif spec.name in ("evidence_detail", "revision_comparison", "all_observations"):
        rows = _obs_join(store)
        if spec.name != "all_observations":
            rows = [r for r in rows if r["revision_id"] in p]
        # Mirror each query's SQL ORDER BY exactly (LIMIT applies after ordering).
        order = {"evidence_detail": ("observation_type", "observation_id"),
                 "revision_comparison": ("revision_id", "observation_type", "observation_id"),
                 "all_observations": ("asset_id", "observation_id")}[spec.name]
        out = sorted(rows, key=lambda r: tuple(r[k] for k in order))
    elif spec.name == "ingestion_batches":
        out = sorted(store.rows("INGESTION_BATCHES"),
                     key=lambda r: (parse_utc(r["started_at_utc"]), r["batch_id"]))
    elif spec.name == "rejected_rows":
        out = sorted(store.rows("REJECTED_ROWS"),
                     key=lambda r: (r["batch_id"], r["source_table"], r["row_ordinal"]))
    elif spec.name == "exclusions":
        out = sorted(store.rows("EXCLUSIONS"),
                     key=lambda r: (r["source_identifier"], r["scope"]))
    else:
        raise QueryError("unknown query")
    return [_upper(r) for r in out[:spec.limit]]


def rows_from_records(records):
    """Snowflake returns upper-case column names; normalise to lower case."""
    def norm(v):
        if isinstance(v, _dt.datetime):
            if v.tzinfo is None:
                raise QueryError("naive timestamp returned; UTC offset required")
            return v.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return v
    return [{str(k).lower(): norm(v) for k, v in r.items()} for r in records]


def present_joined(rows, as_of):
    out = []
    for r in rows:
        rights = None
        if r.get("allowed_use") is not None:
            rights = {"allowed_use": r["allowed_use"],
                      "redistribution_status": r["redistribution_status"]}
        p = present_observation(r, rights, as_of)
        p["asset_id"] = r.get("asset_id")
        p["canonical_locator"] = r.get("canonical_locator")
        p["rights_record_id"] = r.get("rights_record_id")
        out.append(p)
    return out
