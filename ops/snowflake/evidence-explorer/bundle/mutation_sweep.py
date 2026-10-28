"""Single-guard mutation sweep for evidence_core.py (stdlib only).

Each mutant applies ONE textual edit to a temp copy of the review directory
and runs `python -I -B test_evidence_core.py`. KILLED = suite fails;
SURVIVED = suite still passes (a real gap). The clean copy must pass first.
Usage: python -I -B mutation_sweep.py [results.json]
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("evidence_core.py", "make_fixture.py", "streamlit_app.py", "test_evidence_core.py", "fixture_v1.json", "schema.sql", "reader_grants.sql", "test_integration_snowflake.py", "ADR.md", "DATA_FLOW_MANIFEST.md", "mutation_sweep.py", "appstub_smoke.py", "run_local_evidence.py", "verify_receipt.py", "test_verify_receipt.py", "test_emulator_fakesnow.py", "verifier_mutation_sweep.py", "TEST_RESULTS.md", "MANIFEST.json", "emulator_results.json")
CORE = "evidence_core.py"

MUTANTS = [
    ("M00", "BROKEN BASELINE: validate_row accepts everything",
     '    """Closed-schema, row-local validation. Returns None or raises Rejection."""\n',
     '    """Closed-schema, row-local validation. Returns None or raises Rejection."""\n    return None\n'),
    ("M01", "secret field-name guard disabled",
     "if type(key) is not str or SECRET_NAME_RE.search(key):",
     "if type(key) is not str:"),
    ("M02", "secret value guard disabled",
     "        if SECRET_VALUE_RE.search(text):", "        if False:"),
    ("M03", "unknown-field (closed schema) guard disabled",
     '            raise Rejection("UNKNOWN_FIELD", key)', "            pass"),
    ("M04", "missing-field guard disabled",
     '            raise Rejection("MISSING_FIELD", name)', "            return None"),
    ("M05", "enum membership guard disabled",
     "        if value not in spec:", "        if False:"),
    ("M06", "future-timestamp guard disabled",
     "        if when > as_of:", "        if False:"),
    ("M07", "UTC-only: timestamp offsets accepted",
     r'(\.\d{1,6})?Z")', r'(\.\d{1,6})?(Z|[+-]\d{2}:\d{2}))'),
    ("M08", "calendar-invalid date swallowed",
     '    except ValueError:\n        raise Rejection("MALFORMED_TIMESTAMP")',
     '    except ValueError:\n        out = _dt.datetime(2000, 1, 1, tzinfo=_dt.timezone.utc)'),
    ("M09", "mutable revision refs accepted",
     'REVISION_RE = re.compile(r"(git-sha1:', 'REVISION_RE = re.compile(r"([A-Za-z]+|git-sha1:'),
    ("M10", "revision/provider consistency guard disabled",
     '                        if not row["immutable_source_revision"].startswith(prefixes):',
     "                        if False:"),
    ("M11", "content-digest comparison disabled",
     '                        if sha256_hex(content) != row["content_digest"]:',
     "                        if False:"),
    ("M12", "digest check skipped when content absent",
     '                        if type(content) is not bytes:\n                            raise Rejection("DIGEST_UNVERIFIABLE", "content_digest")\n                        if sha256_hex(content) != row["content_digest"]:',
     '                        if type(content) is bytes and sha256_hex(content) != row["content_digest"]:'),
    ("M13", "batch-level manifest idempotency disabled",
     '                if b["input_manifest_digest"] == digest:', "                if False:"),
    ("M14", "identical duplicate row appended instead of skipped",
     "                        if canonical_bytes(prior[0]) == canonical_bytes(row):\n                            skipped += 1\n                            continue",
     "                        if canonical_bytes(prior[0]) == canonical_bytes(row):\n                            skipped += 1"),
    ("M15", "conflicting duplicate id accepted (overwrite risk)",
     '                        raise Rejection("CONFLICTING_DUPLICATE_ID",\n                                        KEY_FIELDS[table][0])',
     "                        pass"),
    ("M16", "ingestion-time exclusion disabled",
     '                        raise Rejection("EXCLUDED")', "                        pass"),
    ("M17", "exclusion prefix-strip disabled (git-sha1:<blob> slips through)",
     '                idents.add(v.split(":", 1)[1])', "                pass"),
    ("M18", "display-scope exclusion disabled",
     '    kept = [r for r in rows if not _excluded(r, exclusions, ("ALL", "DISPLAY"))]',
     "    kept = list(rows)"),
    ("M19", "synthetic label text check disabled",
     "        if value != SYNTHETIC_LABEL:", "        if False:"),
    ("M20", "is_synthetic=TRUE check disabled",
     '        if kind == "synthetic" and value is not True:', "        if False:"),
    ("M21", "secret rejections store a row digest",
     "row_digest = None if secret else sha256_hex(canonical_bytes(row))",
     "row_digest = sha256_hex(canonical_bytes(row))"),
    ("M22", "upper LIMIT bound removed",
     "if type(limit) is not int or limit < 1 or limit > MAX_QUERY_LIMIT:",
     "if type(limit) is not int or limit < 1:"),
    ("M23", "LIMIT exact-int check weakened to isinstance (bool accepted)",
     "if type(limit) is not int or limit < 1 or limit > MAX_QUERY_LIMIT:",
     "if not isinstance(limit, int) or limit < 1 or limit > MAX_QUERY_LIMIT:"),
    ("M24", "provider filter string-concatenated instead of bound",
     '        where = "WHERE a.PROVIDER = ? "\n        params.append(provider)',
     "        where = \"WHERE a.PROVIDER = '%s' \" % provider"),
    ("M25", "identifier parameter validation disabled",
     '    if type(value) is not str or ID_RE.fullmatch(value) is None:\n        raise QueryError("%s is not a valid identifier" % name)',
     "    pass"),
    ("M26", "ERROR state carries rows",
     'return ScreenState("ERROR", [],', "return ScreenState(\"ERROR\", list(rows),"),
    ("M27", "EMPTY reported as OK",
     '        return ScreenState("EMPTY", [],', '        return ScreenState("OK", [],'),
    ("M28", "restricted-rights display guard disabled",
     '    if (rights["allowed_use"] != "METADATA_DISPLAY"\n            or rights["redistribution_status"] == "PROHIBITED"):',
     "    if False:"),
    ("M29", "internal-only rights operand dropped",
     '    if (rights["allowed_use"] != "METADATA_DISPLAY"\n            or rights["redistribution_status"] == "PROHIBITED"):',
     '    if (rights["redistribution_status"] == "PROHIBITED"):'),
    ("M30", "training_allowed evidence guard disabled",
     '        if row["training_allowed"] is True and row["training_evidence_ref"] is None:',
     "        if False:"),
    ("M31", "explicit-missing value consistency disabled",
     '        if present != (row["summarized_value"] is not None):', "        if False:"),
    ("M32", "rights NONE ingestion guard disabled",
     '                        if rights is not None and rights["allowed_use"] == "NONE":',
     "                        if False:"),
    ("M33", "row-count bound disabled",
     '        elif sum(len(v) for v in payload["tables"].values()) > MAX_ROWS_PER_BATCH:',
     "        elif False:"),
    ("M34", "request-size bound disabled",
     "        elif len(raw) > MAX_BATCH_BYTES:", "        elif False:"),
    ("M35", "cost screen accepts unsourced measurement",
     '            or measurement["source"] != "SNOWFLAKE_ACCOUNT_USAGE"):',
     "            or False):"),
    ("M36", "stale threshold widened",
     "STALE_AFTER_DAYS = 90", "STALE_AFTER_DAYS = 9000"),
    ("M37", "MERGE gains WHEN MATCHED UPDATE",
     '           "WHEN NOT MATCHED THEN INSERT (%s) VALUES (%s)"',
     '           "WHEN MATCHED THEN UPDATE SET t.%s = s.%s WHEN NOT MATCHED THEN INSERT (%s) VALUES (%s)"'),
    ("M38", "rejected rows not retained",
     "        store._rejected.extend(rejected)", "        pass"),
    ("M39", "value grammar allows markup",
     'VALUE_RE = re.compile(r"[A-Za-z0-9 .,:;=+_/%()-]{1,64}")',
     'VALUE_RE = re.compile(r"[^\\n]{1,64}")'),
    ("M40", "locator traversal guard disabled",
     '        if LOCATOR_RE.fullmatch(value) is None or ".." in value or "//" in value[8:]:',
     "        if LOCATOR_RE.fullmatch(value) is None:"),
    ("M41", "orphan-reference guard for revisions disabled",
     '                        if not assets:\n                            raise Rejection("ORPHAN_REFERENCE", "asset_id")',
     "                        if not assets:\n                            continue"),
    ("M42", "bool exact-type check weakened",
     '    elif kind in ("bool", "synthetic"):\n        if type(value) is not bool:',
     '    elif kind in ("bool", "synthetic"):\n        if not isinstance(value, int):'),
    ("M43", "all_observations reference order differs from SQL ORDER BY",
     '"all_observations": ("asset_id", "observation_id")}[spec.name]',
     '"all_observations": ("revision_id", "observation_type", "observation_id")}[spec.name]'),
    ("M44", "revision order compares timestamp text, not instants",
     'key=lambda r: (parse_utc(r["observed_at_utc"]), r["revision_id"]))',
     'key=lambda r: (r["observed_at_utc"], r["revision_id"]))'),
    ("M45", "ingestion batches returned in insertion order",
     """        out = sorted(store.rows("INGESTION_BATCHES"),
                     key=lambda r: (parse_utc(r["started_at_utc"]), r["batch_id"]))""",
     '        out = store.rows("INGESTION_BATCHES")'),
    ("M46", "latest-revision tie-break reversed vs SQL",
     "                last = min((r for r in mine", "                last = max((r for r in mine"),
    ("M47", "latest rights compares timestamp text",
     """    return sorted(match, key=lambda r: (parse_utc(r["reviewed_at_utc"]),""",
     """    return sorted(match, key=lambda r: ((r["reviewed_at_utc"]),"""),
]


def run_suite(d):
    r = subprocess.run([sys.executable, "-I", "-B", "test_evidence_core.py"], cwd=d,
                       capture_output=True, timeout=600)
    tail = r.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
    return r.returncode, tail[0]


def main(out_path):
    with open(os.path.join(HERE, CORE), "rb") as fh:
        clean = fh.read().decode("utf-8")
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for f in FILES:
            shutil.copy2(os.path.join(HERE, f), os.path.join(tmp, f))
        rc, tail = run_suite(tmp)
        if rc != 0:
            raise SystemExit("clean copy does not pass: %s" % tail)
        for mid, desc, old, new in MUTANTS:
            n = clean.count(old)
            if n != 1:
                results.append({"id": mid, "description": desc, "status": "INVALID",
                                "detail": "anchor matched %d times" % n})
                continue
            mutated = clean.replace(old, new)
            with open(os.path.join(tmp, CORE), "wb") as fh:
                fh.write(mutated.encode("utf-8"))
            rc, tail = run_suite(tmp)
            results.append({"id": mid, "description": desc,
                            "status": "KILLED" if rc != 0 else "SURVIVED",
                            "detail": tail})
        with open(os.path.join(tmp, CORE), "wb") as fh:
            fh.write(clean.encode("utf-8"))
    summary = {s: sum(1 for r in results if r["status"] == s)
               for s in ("KILLED", "SURVIVED", "INVALID")}
    doc = {"target": CORE, "mutants": len(results), "summary": summary, "results": results}
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    sys.stdout.write(json.dumps(summary) + "\n")
    for r in results:
        sys.stdout.write("%s %-8s %s\n" % (r["id"], r["status"], r["description"]))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "mutation_results.json"))
