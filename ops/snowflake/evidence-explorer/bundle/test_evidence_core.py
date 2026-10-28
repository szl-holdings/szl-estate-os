"""Local checks for the SZL Evidence Explorer (mission section 8, local part).

Run:  python -I -B test_evidence_core.py -v
Stdlib unittest only. No network, no Snowflake, no credentials.
Class names S8_xx map one-to-one onto the section-8 local checks; X_ classes
are supporting static checks (SQL, app, deliverable hygiene).
"""
import ast
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import evidence_core as ec  # noqa: E402
import make_fixture as mf  # noqa: E402
import run_local_evidence as rle  # noqa: E402
import test_integration_snowflake as itest  # noqa: E402

FIXTURE_PATH = os.path.join(HERE, "fixture_v1.json")
FIXTURE_SHA256 = "be43d225497b1f48d445c9c5b53130041889fec614740778cc1b14de406dac72"
ACCOUNT_ID_SHA256 = "5d691aec5aa139b1e2cd078ef32214c7591011b9070a0196b25bcff0ed89d8f0"   # sha256 of the upper-case account identifier
AS_OF = "2026-10-21T00:00:00Z"
AS_OF_DT = ec.parse_utc(AS_OF)
EXPECTED_COUNTS = {"ASSETS": 7, "REVISIONS": 7, "OBSERVATIONS": 21,
                   "RIGHTS_RECORDS": 5, "EXCLUSIONS": 3, "INGESTION_BATCHES": 3,
                   "REJECTED_ROWS": 21}
EXPECTED_REASONS = {
    ("ASSETS", "ENUM_VIOLATION"): 1, ("ASSETS", "EXCLUDED"): 1,
    ("OBSERVATIONS", "CONFLICTING_DUPLICATE_ID"): 1,
    ("OBSERVATIONS", "ENUM_VIOLATION"): 1, ("OBSERVATIONS", "FUTURE_TIMESTAMP"): 1,
    ("OBSERVATIONS", "INCONSISTENT_FIELDS"): 1,
    ("OBSERVATIONS", "MALFORMED_TIMESTAMP"): 2, ("OBSERVATIONS", "MISSING_FIELD"): 1,
    ("OBSERVATIONS", "ORPHAN_REFERENCE"): 2, ("OBSERVATIONS", "RIGHTS_DENIED"): 1,
    ("OBSERVATIONS", "SECRET_FIELD"): 1, ("OBSERVATIONS", "SECRET_VALUE"): 1,
    ("OBSERVATIONS", "SYNTHETIC_LABEL_REQUIRED"): 1,
    ("OBSERVATIONS", "TYPE_VIOLATION"): 1,
    ("REVISIONS", "CONTENT_DIGEST_MISMATCH"): 1, ("REVISIONS", "EXCLUDED"): 1,
    ("REVISIONS", "MALFORMED_REVISION"): 2,
    ("RIGHTS_RECORDS", "INCONSISTENT_FIELDS"): 1}
DELIVERABLES = ("evidence_core.py", "make_fixture.py", "streamlit_app.py",
                "test_evidence_core.py", "test_integration_snowflake.py",
                "schema.sql", "reader_grants.sql", "fixture_v1.json", "ADR.md",
                "DATA_FLOW_MANIFEST.md", "mutation_sweep.py", "appstub_smoke.py",
                "run_local_evidence.py", "verify_receipt.py", "test_verify_receipt.py",
                "test_emulator_fakesnow.py", "verifier_mutation_sweep.py",
                "TEST_RESULTS.md", "MANIFEST.json", "emulator_results.json")


def fixture():
    return mf.load(FIXTURE_PATH)


def content(batch):
    return {k: v.encode("utf-8") for k, v in batch["local_content"].items()}


def loaded_store():
    fx = fixture()
    store = ec.LocalStore()
    results = [ec.ingest_batch(store, b["payload"], fx["as_of_utc"], content(b))
               for b in fx["batches"]]
    return store, results


def good(table):
    fx = fixture()
    rows = fx["batches"][0]["payload"]["tables"][table]
    return copy.deepcopy(rows[0])


def reason(table, row):
    try:
        ec.validate_row(table, row, AS_OF_DT)
    except ec.Rejection as exc:
        return exc.reason
    return None


def read(name):
    with open(os.path.join(HERE, name), "rb") as fh:
        # Git may materialize these text fixtures with CRLF on Windows.  The
        # bundle's semantic checks and approval guard are line-ending
        # independent, so normalize the checkout representation before
        # comparing text.
        return fh.read().replace(b"\r\n", b"\n").decode("utf-8")


def canonical_bytes(path):
    """Read a repository text fixture using its LF canonical representation."""
    with open(path, "rb") as fh:
        return fh.read().replace(b"\r\n", b"\n")


def sql_statements(name):
    lines = [l for l in read(name).splitlines()
             if l.strip() and not l.strip().startswith("--")]
    return "\n".join(lines)


class S8_01_FixtureDeterminismAndCounts(unittest.TestCase):
    def test_build_is_byte_identical_in_process(self):
        self.assertEqual(mf.render(mf.build()), mf.render(mf.build()))

    def test_committed_fixture_matches_generator_and_pinned_hash(self):
        data = canonical_bytes(FIXTURE_PATH)
        self.assertEqual(hashlib.sha256(data).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(data, mf.render(mf.build()))

    def test_fresh_isolated_process_reproduces_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "fx.json")
            subprocess.run([sys.executable, "-I", "-B",
                            os.path.join(HERE, "make_fixture.py"), out],
                           check=True, capture_output=True, timeout=60)
            self.assertEqual(hashlib.sha256(canonical_bytes(out)).hexdigest(),
                             FIXTURE_SHA256)

    def test_input_row_counts(self):
        b = fixture()["batches"]
        t1 = b[0]["payload"]["tables"]
        self.assertEqual({k: len(v) for k, v in t1.items()},
                         {"EXCLUSIONS": 2, "RIGHTS_RECORDS": 6, "ASSETS": 9,
                          "REVISIONS": 10, "OBSERVATIONS": 32})
        self.assertEqual(len(b[1]["payload"]["tables"]["OBSERVATIONS"]), 4)
        self.assertEqual(len(b), 3)

    def test_expected_stored_counts_and_reasons(self):
        store, results = loaded_store()
        self.assertEqual(store.counts(), EXPECTED_COUNTS)
        self.assertEqual([(r["accepted"], r["rejected"], r["skipped_duplicates"])
                          for r in results], [(37, 21, 1), (5, 0, 1), (1, 0, 0)])
        got = {}
        for r in store.rows("REJECTED_ROWS"):
            key = (r["source_table"], r["reason_code"])
            got[key] = got.get(key, 0) + 1
        self.assertEqual(got, EXPECTED_REASONS)

    def test_accepted_observations_in_20_to_30(self):
        store, _ = loaded_store()
        n = len(store.rows("OBSERVATIONS"))
        self.assertTrue(20 <= n <= 30, n)
        providers = {a["provider"] for a in store.rows("ASSETS")}
        self.assertEqual(providers, set(ec.PROVIDERS))


class S8_02_RequiredFieldsAndEnums(unittest.TestCase):
    def test_each_required_field_missing_is_rejected(self):
        for table in ("ASSETS", "REVISIONS", "OBSERVATIONS", "RIGHTS_RECORDS",
                      "EXCLUSIONS"):
            row = good(table)
            self.assertIsNone(reason(table, row), table)
            for name in list(row):
                broken = dict(row)
                del broken[name]
                self.assertEqual(reason(table, broken), "MISSING_FIELD", (table, name))

    def test_unknown_field_rejected(self):
        row = good("ASSETS")
        row["notes"] = "free text"
        self.assertEqual(reason("ASSETS", row), "UNKNOWN_FIELD")

    def test_every_enum_rejects_out_of_set_value(self):
        for table, spec in ec.TABLE_SPECS.items():
            for field in spec:
                if field[1] != "enum":
                    continue
                row = good(table)
                row[field[0]] = "NOT_IN_ENUM"
                self.assertEqual(reason(table, row), "ENUM_VIOLATION", field[0])
                row[field[0]] = field[2][0].swapcase()
                self.assertEqual(reason(table, row), "ENUM_VIOLATION", field[0])

    def test_type_exactness(self):
        row = good("RIGHTS_RECORDS")
        row["training_allowed"] = 0
        self.assertEqual(reason("RIGHTS_RECORDS", row), "TYPE_VIOLATION")
        row = good("OBSERVATIONS")
        row["summarized_value"] = 0.5
        self.assertEqual(reason("OBSERVATIONS", row), "TYPE_VIOLATION")
        self.assertEqual(reason("ASSETS", ["not", "a", "dict"]), "NOT_A_MAPPING")

    def test_explicit_missing_value_consistency(self):
        row = good("OBSERVATIONS")
        row["value_state"] = "MISSING"
        self.assertEqual(reason("OBSERVATIONS", row), "INCONSISTENT_FIELDS")
        row["summarized_value"] = None
        self.assertIsNone(reason("OBSERVATIONS", row))
        row = good("OBSERVATIONS")
        row["summarized_value"] = None
        self.assertEqual(reason("OBSERVATIONS", row), "INCONSISTENT_FIELDS")

    def test_training_allowed_needs_evidence(self):
        row = good("RIGHTS_RECORDS")
        self.assertIs(row["training_allowed"], False)
        row["training_allowed"] = True
        self.assertEqual(reason("RIGHTS_RECORDS", row), "INCONSISTENT_FIELDS")
        row["training_evidence_ref"] = "approval:demo-0001"
        self.assertIsNone(reason("RIGHTS_RECORDS", row))

    def test_bounded_lengths(self):
        row = good("OBSERVATIONS")
        row["summarized_value"] = "x" * 64
        self.assertIsNone(reason("OBSERVATIONS", row))
        row["summarized_value"] = "x" * 65
        self.assertEqual(reason("OBSERVATIONS", row), "MALFORMED_FIELD")
        row = good("ASSETS")
        row["asset_id"] = "a" * 64
        self.assertIsNone(reason("ASSETS", row))
        row["asset_id"] = "a" * 65
        self.assertEqual(reason("ASSETS", row), "MALFORMED_FIELD")
        row = good("ASSETS")
        row["canonical_locator"] = "mock://github/" + "a" * 199
        self.assertIsNone(reason("ASSETS", row))
        row["canonical_locator"] = "mock://github/" + "a" * 200
        self.assertEqual(reason("ASSETS", row), "MALFORMED_FIELD")

    def test_markup_and_traversal_refused_in_values(self):
        row = good("OBSERVATIONS")
        for bad in ("<script>x</script>", "a & b", "quote\"", "line\nbreak"):
            row["summarized_value"] = bad
            self.assertEqual(reason("OBSERVATIONS", row), "MALFORMED_FIELD", bad)
        row = good("OBSERVATIONS")
        row["source_locator"] = "mock://github/demo-org/../etc"
        self.assertEqual(reason("OBSERVATIONS", row), "MALFORMED_FIELD")


class S8_03_MalformedTimestampAndRevision(unittest.TestCase):
    def test_malformed_timestamps(self):
        for bad in ("2026-02-30T00:00:00Z", "2026-10-01T10:00:00+02:00",
                    "2026-10-01T10:00:00", "2026-10-01 10:00:00Z",
                    "2026-10-01T25:00:00Z", "1999-12-31T23:59:59Z",
                    "2026-10-01T10:00:00.1234567Z", ""):
            row = good("OBSERVATIONS")
            row["observed_at_utc"] = bad
            self.assertEqual(reason("OBSERVATIONS", row), "MALFORMED_TIMESTAMP", bad)

    def test_future_timestamp(self):
        row = good("OBSERVATIONS")
        row["observed_at_utc"] = "2026-10-21T00:00:01Z"
        self.assertEqual(reason("OBSERVATIONS", row), "FUTURE_TIMESTAMP")
        row["observed_at_utc"] = AS_OF
        self.assertIsNone(reason("OBSERVATIONS", row))

    def test_fractional_seconds_accepted(self):
        row = good("OBSERVATIONS")
        row["observed_at_utc"] = "2026-10-20T00:00:00.250000Z"
        self.assertIsNone(reason("OBSERVATIONS", row))

    def test_mutable_or_malformed_revisions(self):
        for bad in ("main", "HEAD", "latest", "git-sha1:" + "a" * 39,
                    "git-sha1:" + "A" * 40, "hf-commit:" + "g" * 40, "sha1:" + "a" * 40):
            row = good("REVISIONS")
            row["immutable_source_revision"] = bad
            self.assertEqual(reason("REVISIONS", row), "MALFORMED_REVISION", bad)

    def test_revision_must_match_provider(self):
        store, _ = loaded_store()
        rej = {(r["source_table"], r["row_ordinal"]): r for r in store.rows("REJECTED_ROWS")}
        revs = fixture()["batches"][0]["payload"]["tables"]["REVISIONS"]
        ords = {r["revision_id"]: i for i, r in enumerate(revs)}
        self.assertEqual(rej[("REVISIONS", ords["demo-rev-probe-wrong"])]["reason_code"],
                         "MALFORMED_REVISION")
        self.assertEqual(rej[("REVISIONS", ords["demo-rev-kit-mutable"])]["reason_code"],
                         "MALFORMED_REVISION")


class S8_04_ContentDigest(unittest.TestCase):
    def test_mismatch_detected_and_retained(self):
        store, _ = loaded_store()
        self.assertNotIn("demo-rev-advisory-bad",
                         {r["revision_id"] for r in store.rows("REVISIONS")})
        reasons = [r for r in store.rows("REJECTED_ROWS")
                   if r["reason_code"] == "CONTENT_DIGEST_MISMATCH"]
        self.assertEqual(len(reasons), 1)
        self.assertEqual(reasons[0]["field_name"], "content_digest")

    def test_single_byte_change_detected(self):
        fx = fixture()
        b = fx["batches"][1]
        lc = content(b)
        lc["demo-rev-kit-b"] = lc["demo-rev-kit-b"] + b" "
        store = ec.LocalStore()
        first = fx["batches"][0]
        ec.ingest_batch(store, first["payload"], AS_OF, content(first))
        res = ec.ingest_batch(store, b["payload"], AS_OF, lc)
        codes = [r["reason_code"] for r in store.rows("REJECTED_ROWS")
                 if r["batch_id"] == res["batch"]["batch_id"]]
        self.assertIn("CONTENT_DIGEST_MISMATCH", codes)

    def test_missing_content_is_unverifiable_not_accepted(self):
        fx = fixture()
        store = ec.LocalStore()
        b = fx["batches"][0]
        res = ec.ingest_batch(store, b["payload"], AS_OF, {})
        self.assertEqual(len(store.rows("REVISIONS")), 0)
        codes = {r["reason_code"] for r in store.rows("REJECTED_ROWS")
                 if r["source_table"] == "REVISIONS"}
        self.assertIn("DIGEST_UNVERIFIABLE", codes)
        self.assertEqual(res["batch"]["status"], "COMPLETED_WITH_REJECTIONS")

    def test_digest_grammar(self):
        row = good("REVISIONS")
        row["content_digest"] = row["content_digest"].upper()
        self.assertEqual(reason("REVISIONS", row), "MALFORMED_FIELD")


class S8_05_DuplicateBatch(unittest.TestCase):
    def test_rerun_is_idempotent_without_row_growth(self):
        store, results = loaded_store()
        before = store.counts()
        fx = fixture()
        for b in fx["batches"]:
            res = ec.ingest_batch(store, b["payload"], AS_OF, content(b))
            self.assertTrue(res["duplicate"])
            self.assertEqual(res["accepted"], 0)
        self.assertEqual(store.counts(), before)

    def test_rerun_returns_original_batch_record(self):
        store, results = loaded_store()
        b = fixture()["batches"][0]
        res = ec.ingest_batch(store, b["payload"], AS_OF, content(b))
        self.assertEqual(res["batch"], results[0]["batch"])
        self.assertEqual(results[0]["batch"]["input_manifest_digest"],
                         ec.manifest_digest(b["payload"]))

    def test_identical_row_skipped_conflicting_row_rejected(self):
        store, results = loaded_store()
        self.assertEqual(results[0]["skipped_duplicates"], 1)
        obs = [o for o in store.rows("OBSERVATIONS")
               if o["observation_id"] == "demo-obs-kit-a-score"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["summarized_value"], "0.71 (illustrative)")

    def test_new_payload_reusing_ids_cannot_overwrite(self):
        store, _ = loaded_store()
        b = copy.deepcopy(fixture()["batches"][1])
        b["payload"]["source_revision"] = "fixture-v1-batch-2-replay"
        b["payload"]["tables"]["OBSERVATIONS"][0]["summarized_value"] = "0.99 (illustrative)"
        res = ec.ingest_batch(store, b["payload"], AS_OF, content(b))
        self.assertFalse(res["duplicate"])
        self.assertEqual(res["accepted"], 0)
        codes = [r["reason_code"] for r in store.rows("REJECTED_ROWS")
                 if r["batch_id"] == res["batch"]["batch_id"]]
        self.assertEqual(codes, ["CONFLICTING_DUPLICATE_ID"])
        self.assertEqual(len(store.rows("OBSERVATIONS")), EXPECTED_COUNTS["OBSERVATIONS"])

    def test_concurrent_identical_batches_ingest_once(self):
        fx = fixture()
        store = ec.LocalStore()
        b = fx["batches"][0]
        out = []
        threads = [threading.Thread(target=lambda: out.append(
            ec.ingest_batch(store, b["payload"], AS_OF, content(b)))) for _ in range(6)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(sum(1 for r in out if not r["duplicate"]), 1)
        self.assertEqual(store.counts()["INGESTION_BATCHES"], 1)
        self.assertEqual(store.counts()["OBSERVATIONS"], 17)

    def test_store_exposes_no_delete_or_reset(self):
        names = {n for n in dir(ec.LocalStore) if not n.startswith("_")}
        self.assertEqual(names, {"rows", "counts"})
        src = read("evidence_core.py")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("remove", "pop", "clear"), node.lineno)
            self.assertNotIsInstance(node, ast.Delete)

    def test_rows_returned_are_copies(self):
        store, _ = loaded_store()
        store.rows("OBSERVATIONS")[0]["summarized_value"] = "tampered"
        self.assertNotIn("tampered", [o["summarized_value"] for o in store.rows("OBSERVATIONS")])

    def test_oversize_and_malformed_batches_fail_closed(self):
        store = ec.LocalStore()
        row = good("EXCLUSIONS")
        many = []
        for i in range(ec.MAX_ROWS_PER_BATCH + 1):
            r = dict(row)
            r["source_identifier"] = "mock-excl-%04d" % i
            many.append(r)
        res = ec.ingest_batch(store, {"source_revision": "big",
                                      "tables": {"EXCLUSIONS": many}}, AS_OF)
        self.assertEqual((res["batch"]["status"], res["batch"]["error_summary"]),
                         ("FAILED", "TOO_MANY_ROWS"))
        wide = [{"padding": "x" * 1000} for _ in range(300)]
        res = ec.ingest_batch(store, {"source_revision": "wide",
                                      "tables": {"EXCLUSIONS": wide}}, AS_OF)
        self.assertEqual(res["batch"]["error_summary"], "REQUEST_TOO_LARGE")
        res = ec.ingest_batch(store, {"source_revision": "nan",
                                      "tables": {"OBSERVATIONS": [{"x": float("nan")}]}},
                              AS_OF)
        self.assertEqual(res["batch"]["error_summary"], "MALFORMED_BATCH")
        res = ec.ingest_batch(store, {"source_revision": "x", "tables": {"USERS": []}}, AS_OF)
        self.assertEqual(res["batch"]["error_summary"], "MALFORMED_BATCH")
        self.assertEqual(store.counts()["EXCLUSIONS"], 0)

    def test_error_summary_is_bounded_and_value_free(self):
        store, results = loaded_store()
        summary = results[0]["batch"]["error_summary"]
        self.assertLessEqual(len(summary), 256)
        self.assertTrue(re.fullmatch(r"[A-Z_]+=\d+(;[A-Z_]+=\d+)*(;\+\d+_MORE)?", summary))


class S8_06_ExclusionEnforcement(unittest.TestCase):
    def test_preserved_studio_blob_never_ingested(self):
        store, _ = loaded_store()
        blob = mf.STUDIO_BLOB
        self.assertEqual(blob, "f75070d94bc3683a7aa18e3d111cb0dd112638c1")
        self.assertIn(blob, {e["source_identifier"] for e in store.rows("EXCLUSIONS")})
        for t in ("ASSETS", "REVISIONS", "OBSERVATIONS", "RIGHTS_RECORDS"):
            self.assertNotIn(blob, json.dumps(store.rows(t)), t)
        revs = fixture()["batches"][0]["payload"]["tables"]["REVISIONS"]
        idx = [i for i, r in enumerate(revs) if r["revision_id"] == "demo-rev-studio-copy"][0]
        rej = [r for r in store.rows("REJECTED_ROWS")
               if r["source_table"] == "REVISIONS" and r["row_ordinal"] == idx]
        self.assertEqual(rej[0]["reason_code"], "EXCLUDED")

    def test_excluded_locator_asset_rejected(self):
        store, _ = loaded_store()
        self.assertNotIn("demo-gh-scraped-forum",
                         {a["asset_id"] for a in store.rows("ASSETS")})

    def test_exclusion_added_later_blocks_new_ingestion(self):
        store, _ = loaded_store()
        row = good("ASSETS")
        row["asset_id"] = "demo-gh-later-excluded"
        row["canonical_locator"] = "mock://github/demo-org/later-excluded"
        excl = {"source_identifier": "demo-gh-later-excluded",
                "exclusion_reason": "OWNER_EXCLUSION",
                "effective_at_utc": "2026-10-20T00:00:00Z", "scope": "INGESTION"}
        ec.ingest_batch(store, {"source_revision": "ex", "tables": {"EXCLUSIONS": [excl]}}, AS_OF)
        res = ec.ingest_batch(store, {"source_revision": "late", "tables": {"ASSETS": [row]}},
                              AS_OF)
        self.assertEqual(res["accepted"], 0)
        self.assertNotIn("demo-gh-later-excluded", {a["asset_id"] for a in store.rows("ASSETS")})

    def test_display_scope_exclusion_hides_and_counts(self):
        store, _ = loaded_store()
        rows = ec.present_joined(ec.rows_from_records(
            ec.local_execute(store, ec.q_all_observations())), AS_OF)
        excl = ec.rows_from_records(ec.local_execute(store, ec.q_exclusions()))
        kept, hidden = ec.apply_display_exclusions(rows, excl)
        self.assertEqual(hidden, 1)
        self.assertNotIn("demo-obs-adv-card", {r["observation_id"] for r in kept})
        self.assertIn("demo-obs-adv-card",
                      {o["observation_id"] for o in store.rows("OBSERVATIONS")})

    def test_display_scope_does_not_block_ingestion(self):
        store = ec.LocalStore()
        excl = good("EXCLUSIONS")
        excl.update({"source_identifier": "demo-gh-display-only", "scope": "DISPLAY"})
        row = good("ASSETS")
        row["asset_id"] = "demo-gh-display-only"
        res = ec.ingest_batch(store, {"source_revision": "d",
                                      "tables": {"EXCLUSIONS": [excl], "ASSETS": [row]}}, AS_OF)
        self.assertEqual(res["accepted"], 2)

    def test_orphan_revision_retained_as_rejection_not_dropped(self):
        store = ec.LocalStore()
        rev = good("REVISIONS")
        rev["asset_id"] = "demo-gh-does-not-exist"
        res = ec.ingest_batch(store, {"source_revision": "orphan",
                                      "tables": {"REVISIONS": [rev]}}, AS_OF,
                              {rev["revision_id"]: b"irrelevant"})
        self.assertEqual((res["accepted"], res["rejected"]), (0, 1))
        rej = store.rows("REJECTED_ROWS")
        self.assertEqual([(r["reason_code"], r["field_name"]) for r in rej],
                         [("ORPHAN_REFERENCE", "asset_id")])

    def test_every_input_row_is_accounted_for(self):
        store, results = loaded_store()
        fx = fixture()
        for b, res in zip(fx["batches"], results):
            n = sum(len(v) for v in b["payload"]["tables"].values())
            self.assertEqual(res["accepted"] + res["rejected"] + res["skipped_duplicates"], n)

    def test_rights_denied_observation_rejected(self):
        store, _ = loaded_store()
        self.assertNotIn("demo-obs-den-card",
                         {o["observation_id"] for o in store.rows("OBSERVATIONS")})


class S8_07_SyntheticLabel(unittest.TestCase):
    def test_label_text_exact(self):
        self.assertEqual(ec.SYNTHETIC_LABEL,
                         "SYNTHETIC DEMONSTRATION DATA \u2014 NOT PRODUCTION OR MODEL "
                         "QUALIFICATION.")
        self.assertEqual(mf.LABEL, ec.SYNTHETIC_LABEL)

    def test_every_stored_row_is_synthetic_and_labelled(self):
        store, _ = loaded_store()
        for t in ("ASSETS", "REVISIONS", "OBSERVATIONS", "RIGHTS_RECORDS"):
            for r in store.rows(t):
                self.assertIs(r["is_synthetic"], True)
                self.assertEqual(r["data_label"], ec.SYNTHETIC_LABEL)

    def test_non_synthetic_or_relabelled_rows_refused(self):
        row = good("ASSETS")
        row["is_synthetic"] = False
        self.assertEqual(reason("ASSETS", row), "SYNTHETIC_LABEL_REQUIRED")
        row = good("ASSETS")
        row["data_label"] = "PRODUCTION DATA"
        self.assertEqual(reason("ASSETS", row), "SYNTHETIC_LABEL_REQUIRED")
        row = good("ASSETS")
        row["data_label"] = ec.SYNTHETIC_LABEL.replace("\u2014", "-")
        self.assertEqual(reason("ASSETS", row), "SYNTHETIC_LABEL_REQUIRED")

    def test_label_survives_presentation(self):
        store, _ = loaded_store()
        rows = ec.present_joined(ec.rows_from_records(
            ec.local_execute(store, ec.q_all_observations())), AS_OF)
        self.assertTrue(rows)
        self.assertTrue(all(r["data_label"] == ec.SYNTHETIC_LABEL and r["is_synthetic"] is True
                            for r in rows))

    def test_app_shows_label_banner_before_any_query(self):
        src = read("streamlit_app.py")
        self.assertLess(src.index("st.warning(core.SYNTHETIC_LABEL)"),
                        src.index("SESSION, SESSION_ERROR = get_live_session()"))

    def test_fixture_values_are_marked_illustrative(self):
        fx = fixture()
        for b in fx["batches"]:
            for o in b["payload"]["tables"].get("OBSERVATIONS", []):
                if o.get("observation_type") == "ILLUSTRATIVE_SCORE" and \
                        o.get("value_state") == "PRESENT" and \
                        type(o.get("summarized_value")) is str and \
                        o["summarized_value"][0].isdigit():
                    self.assertIn("(illustrative)", o["summarized_value"])
        for b in fx["batches"]:
            for a in b["payload"]["tables"].get("ASSETS", []):
                self.assertTrue(a["canonical_locator"].startswith("mock://"))


class S8_08_NoSecretBearingFields(unittest.TestCase):
    def test_secret_like_field_names_rejected(self):
        for name in ("api_token", "password", "Secret", "private_key", "apiKey",
                     "credential_ref", "bearer", "session_id", "cookie", "auth_header"):
            row = good("ASSETS")
            row[name] = "x"
            self.assertEqual(reason("ASSETS", row), "SECRET_FIELD", name)

    def test_secret_like_values_rejected(self):
        for value in ("ghp_SYNTHETICDEMONOTREAL", "AKIA" + "A" * 16,
                      "-----BEGIN PRIVATE KEY-----", "hf_" + "a" * 30,
                      "eyJhbGciOiJIUzI1NiJ9.e30.x"):
            row = good("OBSERVATIONS")
            row["summarized_value"] = value
            self.assertEqual(reason("OBSERVATIONS", row), "SECRET_VALUE", value)

    def test_secret_rejections_store_no_digest_and_no_value(self):
        store, _ = loaded_store()
        sec = [r for r in store.rows("REJECTED_ROWS")
               if r["reason_code"] in ("SECRET_FIELD", "SECRET_VALUE")]
        self.assertEqual(len(sec), 2)
        for r in sec:
            self.assertIsNone(r["row_digest"])
            self.assertIsNone(r["field_name"])
        dump = json.dumps(store.rows("REJECTED_ROWS")) + json.dumps(store.rows("INGESTION_BATCHES"))
        self.assertNotIn("ghp_", dump)
        self.assertNotIn("api_token", dump)

    def test_no_schema_column_is_secret_named(self):
        for table, spec in ec.TABLE_SPECS.items():
            for f in spec:
                self.assertIsNone(ec.SECRET_NAME_RE.search(f[0]), f[0])
        cols = re.findall(r"^\s+([A-Z_]+) (?:VARCHAR|BOOLEAN|TIMESTAMP_TZ|NUMBER)",
                          read("schema.sql"), re.M)
        self.assertGreater(len(cols), 40)
        for c in cols:
            self.assertIsNone(ec.SECRET_NAME_RE.search(c), c)

    def test_deliverables_contain_no_token_shapes_or_account_identifier(self):
        allowed = {"ghp_SYNTHETICDEMONOTREAL", "-----BEGIN", "github_pat_",
                   "eyJhbGciOiJIUzI1NiJ9."}
        token = re.compile(r"\b([A-Za-z0-9]{3,12})[-._]([A-Za-z0-9]{3,12})\b")
        for name in DELIVERABLES:
            path = os.path.join(HERE, name)
            if not os.path.exists(path):
                continue
            text = read(name)
            for m in ec.SECRET_VALUE_RE.finditer(text):
                self.assertIn(m.group(0), allowed, (name, m.group(0)))
            for m in token.finditer(text):
                cand = (m.group(1) + "-" + m.group(2)).upper()
                self.assertNotEqual(hashlib.sha256(cand.encode()).hexdigest(),
                                    ACCOUNT_ID_SHA256, name)
            self.assertIsNone(re.search(r"snowflakecomputing\.com", text), name)

    def test_core_has_no_network_or_credential_imports(self):
        tree = ast.parse(read("evidence_core.py"))
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add(node.module.split(".")[0])
        self.assertEqual(mods, {"datetime", "hashlib", "json", "re", "threading",
                                "collections"})
        self.assertNotIn("os.environ", read("evidence_core.py"))


class S8_09_ParameterizedQueries(unittest.TestCase):
    INJECT = "x' OR '1'='1"

    def test_user_values_are_bound_not_concatenated(self):
        spec = ec.q_asset_inventory("GITHUB")
        self.assertIn("a.PROVIDER = ?", spec.sql)
        self.assertEqual(spec.params, ("GITHUB",))
        self.assertNotIn("'GITHUB'", spec.sql)
        spec = ec.q_evidence_detail("demo-rev-kit-a")
        self.assertEqual(spec.params, ("demo-rev-kit-a",))
        self.assertNotIn("demo-rev-kit-a", spec.sql)
        spec = ec.q_revision_comparison("demo-rev-kit-a", "demo-rev-kit-b")
        self.assertEqual(spec.sql.count("?"), 2)
        self.assertEqual(spec.params, ("demo-rev-kit-a", "demo-rev-kit-b"))
        spec = ec.q_asset_revisions("demo-gh-evidence-kit")
        self.assertEqual(spec.params, ("demo-gh-evidence-kit",))
        self.assertNotIn("demo-gh-evidence-kit", spec.sql)

    def test_injection_attempts_refused_before_sql_is_built(self):
        for fn in (ec.q_evidence_detail, ec.q_asset_revisions):
            for bad in (self.INJECT, "demo; DROP TABLE x", "", None, 5, "A" * 3):
                with self.assertRaises(ec.QueryError):
                    fn(bad)
        with self.assertRaises(ec.QueryError):
            ec.q_asset_inventory(self.INJECT)
        with self.assertRaises(ec.QueryError):
            ec.q_revision_comparison("demo-rev-kit-a", "demo-rev-kit-a")
        with self.assertRaises(ec.QueryError):
            ec.q_asset_inventory(schema="SZL_EE_DB.EE_DATA; DROP")

    def test_placeholder_count_matches_params_for_all_builders(self):
        specs = [ec.q_asset_inventory(), ec.q_asset_inventory("RUNTIME"),
                 ec.q_asset_revisions("demo-gh-evidence-kit"),
                 ec.q_evidence_detail("demo-rev-kit-a"),
                 ec.q_revision_comparison("demo-rev-kit-a", "demo-rev-kit-b"),
                 ec.q_all_observations(), ec.q_ingestion_batches(),
                 ec.q_rejected_rows(), ec.q_exclusions()]
        for s in specs:
            self.assertEqual(s.sql.count("?"), len(s.params), s.name)
            self.assertTrue(s.sql.startswith("/* q:%s */ SELECT " % s.name), s.name)
            self.assertNotIn("'", s.sql, s.name)
            for kw in ("INSERT", "UPDATE", "DELETE", "MERGE", "DROP", "TRUNCATE"):
                self.assertNotRegex(s.sql.upper(), r"(?<![A-Z_])%s(?![A-Z_])" % kw, s.name)

    def test_merge_is_insert_only_and_bound(self):
        store, _ = loaded_store()
        for table in ("ASSETS", "REVISIONS", "OBSERVATIONS", "RIGHTS_RECORDS", "EXCLUSIONS",
                      "INGESTION_BATCHES", "REJECTED_ROWS"):
            row = store.rows(table)[0]
            spec = ec.build_merge(table, row)
            self.assertEqual(spec.sql.count("?"), len(row))
            self.assertEqual(len(spec.params), len(row))
            self.assertIn("WHEN NOT MATCHED THEN INSERT", spec.sql)
            for kw in ("UPDATE", "DELETE", "WHEN MATCHED THEN"):
                self.assertNotIn(kw, spec.sql)
            self.assertNotIn("'", spec.sql)
        with self.assertRaises(ec.QueryError):
            ec.build_merge("ASSETS", {"asset_id": "x"})
        with self.assertRaises(ec.QueryError):
            ec.build_merge("USERS", {})


class S8_10_BoundedResultLimits(unittest.TestCase):
    def test_limit_bounds(self):
        self.assertTrue(ec.q_asset_inventory().sql.endswith("LIMIT %d" % ec.DEFAULT_QUERY_LIMIT))
        self.assertTrue(ec.q_ingestion_batches(limit=ec.MAX_QUERY_LIMIT).sql.endswith("LIMIT 200"))
        for bad in (0, -1, ec.MAX_QUERY_LIMIT + 1, 10 ** 9, True, 5.0, "10", None):
            with self.assertRaises(ec.QueryError, msg=repr(bad)):
                ec.q_ingestion_batches(limit=bad)

    def test_every_read_query_has_exactly_one_trailing_limit(self):
        for s in (ec.q_asset_inventory(), ec.q_all_observations(), ec.q_exclusions(),
                  ec.q_rejected_rows(), ec.q_evidence_detail("demo-rev-kit-a")):
            self.assertEqual(len(re.findall(r"\bLIMIT\b", s.sql)), 1)
            self.assertRegex(s.sql, r"LIMIT \d+$")
            self.assertLessEqual(s.limit, ec.MAX_QUERY_LIMIT)

    def test_local_execution_respects_limit_and_flags_truncation(self):
        store, _ = loaded_store()
        spec = ec.q_all_observations(limit=5)
        rows = ec.local_execute(store, spec)
        self.assertEqual(len(rows), 5)
        st = ec.screen_state(rows, None, spec.limit)
        self.assertTrue(st.truncated)
        self.assertIn("limit reached", st.message)
        st = ec.screen_state(rows[:3], None, spec.limit)
        self.assertFalse(st.truncated)


class S8_10b_ReferenceOrderingMatchesSql(unittest.TestCase):
    """local_execute must mirror each SQL ORDER BY, because LIMIT applies after
    ordering (found by the fakesnow emulator check, 2026-10-21)."""

    def test_all_observations_truncation_matches_sql_order(self):
        store, _ = loaded_store()
        full = ec.local_execute(store, ec.q_all_observations())
        keys = [(r["ASSET_ID"], r["OBSERVATION_ID"]) for r in full]
        self.assertEqual(keys, sorted(keys))
        self.assertIn("ORDER BY a.ASSET_ID, o.OBSERVATION_ID", ec.q_all_observations().sql)
        top = ec.local_execute(store, ec.q_all_observations(limit=5))
        self.assertEqual(top, full[:5])

    def test_detail_and_comparison_order(self):
        store, _ = loaded_store()
        d = ec.local_execute(store, ec.q_evidence_detail("demo-rev-kit-a"))
        self.assertEqual([(r["OBSERVATION_TYPE"], r["OBSERVATION_ID"]) for r in d],
                         sorted((r["OBSERVATION_TYPE"], r["OBSERVATION_ID"]) for r in d))
        spec = ec.q_revision_comparison("demo-rev-kit-a", "demo-rev-kit-b")
        self.assertIn("ORDER BY o.REVISION_ID, o.OBSERVATION_TYPE, o.OBSERVATION_ID", spec.sql)
        c = ec.local_execute(store, spec)
        k = [(r["REVISION_ID"], r["OBSERVATION_TYPE"], r["OBSERVATION_ID"]) for r in c]
        self.assertEqual(k, sorted(k))

    def test_batches_ordered_by_start_then_id(self):
        store, _ = loaded_store()
        ids = [r["BATCH_ID"] for r in ec.local_execute(store, ec.q_ingestion_batches())]
        self.assertEqual(ids, sorted(ids))
        self.assertNotEqual([b["batch_id"] for b in store.rows("INGESTION_BATCHES")], ids)

    def _two_revision_store(self, t_a, t_b, id_a="demo-rev-t-a", id_b="demo-rev-t-b"):
        asset = good("ASSETS")
        asset["asset_id"] = "demo-gh-time"
        revs, content = [], {}
        for rid, ts in ((id_a, t_a), (id_b, t_b)):
            r = good("REVISIONS")
            body = ("body " + rid).encode()
            r.update(revision_id=rid, asset_id="demo-gh-time", observed_at_utc=ts,
                     content_digest=ec.sha256_hex(body))
            revs.append(r)
            content[rid] = body
        store = ec.LocalStore()
        res = ec.ingest_batch(store, {"source_revision": "t", "tables": {
            "ASSETS": [asset], "REVISIONS": revs}}, AS_OF, content)
        self.assertEqual(res["accepted"], 3)
        return store

    def test_fractional_seconds_order_by_instant_not_text(self):
        store = self._two_revision_store("2026-10-18T06:00:00Z", "2026-10-18T06:00:00.250000Z")
        inv = ec.local_execute(store, ec.q_asset_inventory())
        self.assertEqual(inv[0]["REVISION_ID"], "demo-rev-t-b")
        revs = ec.local_execute(store, ec.q_asset_revisions("demo-gh-time"))
        self.assertEqual([r["REVISION_ID"] for r in revs], ["demo-rev-t-a", "demo-rev-t-b"])

    def test_latest_revision_tie_breaks_to_smallest_id_like_sql(self):
        store = self._two_revision_store("2026-10-18T06:00:00Z", "2026-10-18T06:00:00Z",
                                         id_a="demo-rev-t-z", id_b="demo-rev-t-a")
        inv = ec.local_execute(store, ec.q_asset_inventory())
        self.assertEqual(inv[0]["REVISION_ID"], "demo-rev-t-a")
        self.assertIn("r.OBSERVED_AT_UTC DESC NULLS LAST, r.REVISION_ID)", ec.q_asset_inventory().sql)

    def test_latest_rights_by_instant(self):
        a = {"source_locator": "mock://github/x", "rights_record_id": "demo-rr-a",
             "reviewed_at_utc": "2026-10-01T00:00:00.500000Z"}
        b = dict(a, rights_record_id="demo-rr-b", reviewed_at_utc="2026-10-01T00:00:00Z")
        self.assertEqual(ec.latest_rights([a, b], "mock://github/x")["rights_record_id"],
                         "demo-rr-a")


class S8_11_TruthfulEmptyErrorStates(unittest.TestCase):
    def test_error_never_carries_rows(self):
        st = ec.screen_state([{"a": 1}], "ProgrammingError", 50)
        self.assertEqual((st.state, st.rows), ("ERROR", []))
        self.assertIn("nothing is cached or simulated", st.message)

    def test_empty_is_not_ok(self):
        st = ec.screen_state([], None, 50)
        self.assertEqual(st.state, "EMPTY")
        self.assertIn("not evidence that upstream evidence is absent", st.message)

    def test_cost_screen_not_measured_without_real_record(self):
        self.assertEqual(ec.cost_status(None)["state"], "NOT_MEASURED")
        self.assertIn("not measured", ec.cost_status(None)["message"])
        fake = {"source": "ESTIMATE", "measured_at_utc": AS_OF, "credits_used": 0.1,
                "query_count": 3}
        self.assertEqual(ec.cost_status(fake)["state"], "NOT_MEASURED")
        partial = {"source": "SNOWFLAKE_ACCOUNT_USAGE", "credits_used": 0.1}
        self.assertEqual(ec.cost_status(partial)["state"], "NOT_MEASURED")
        real = dict(fake, source="SNOWFLAKE_ACCOUNT_USAGE")
        self.assertEqual(ec.cost_status(real)["state"], "MEASURED")

    def test_missing_stale_restricted_shown_not_hidden(self):
        store, _ = loaded_store()
        rows = ec.present_joined(ec.rows_from_records(
            ec.local_execute(store, ec.q_all_observations())), AS_OF)
        by = {r["observation_id"]: r for r in rows}
        self.assertEqual(by["demo-obs-adv-score"]["display_value"], "MISSING")
        self.assertEqual(by["demo-obs-prb-score"]["display_value"], "NOT_MEASURED")
        self.assertEqual(by["demo-obs-tel-card"]["display_value"], "WITHHELD: RIGHTS_RESTRICTED")
        self.assertEqual(by["demo-obs-prb-probe"]["display_value"], "WITHHELD: RIGHTS_UNKNOWN")
        self.assertEqual(by["demo-obs-ver-a-score"]["freshness"], "STALE")
        self.assertEqual(by["demo-obs-kit-b-score"]["freshness"], "CURRENT")
        gaps = {g["observation_id"]: g["gap_reasons"] for g in ec.classify_gaps(rows)}
        self.assertEqual(gaps["demo-obs-ver-a-card"], "MISSING,STALE")
        self.assertEqual(len(gaps), 10)
        inv = ec.rows_from_records(ec.local_execute(store, ec.q_asset_inventory()))
        ig = {g["asset_id"]: g["gap_reasons"] for g in ec.inventory_gaps(inv, rows)}
        self.assertEqual(ig, {"demo-gh-studio-copy": "NO_ACCEPTED_REVISION",
                              "demo-hf-denied-corpus": "NO_ACCEPTED_OBSERVATIONS"})

    def test_internal_only_rights_withheld_even_if_redistribution_allowed(self):
        obs = {"value_state": "PRESENT", "summarized_value": "v"}
        self.assertEqual(ec.display_value(obs, {"allowed_use": "METADATA_INTERNAL",
                                                "redistribution_status": "ALLOWED"})[1],
                         "RIGHTS_RESTRICTED")
        self.assertEqual(ec.display_value(obs, {"allowed_use": "METADATA_DISPLAY",
                                                "redistribution_status": "PROHIBITED"})[1],
                         "RIGHTS_RESTRICTED")
        self.assertEqual(ec.display_value(obs, {"allowed_use": "METADATA_DISPLAY",
                                                "redistribution_status": "ALLOWED"}),
                         ("v", "SHOWN"))

    def test_stale_boundary(self):
        self.assertEqual(ec.freshness("2026-07-23T00:00:00Z", AS_OF), "CURRENT")
        self.assertEqual(ec.freshness("2026-07-22T00:00:00Z", AS_OF), "STALE")

    def test_revision_comparison_is_descriptive(self):
        store, _ = loaded_store()
        spec = ec.q_revision_comparison("demo-rev-kit-a", "demo-rev-kit-b")
        rows = ec.present_joined(ec.rows_from_records(ec.local_execute(store, spec)), AS_OF)
        cmp = {c["observation_type"]: c["change"] for c in ec.compare_revisions(
            [r for r in rows if r["revision_id"] == "demo-rev-kit-a"],
            [r for r in rows if r["revision_id"] == "demo-rev-kit-b"])}
        self.assertEqual(cmp, {"CARD_FIELD": "SAME", "CHECKSUM_RECORD": "ONLY_IN_A",
                               "ILLUSTRATIVE_SCORE": "DIFFERENT",
                               "RUNTIME_PROBE": "NOT_COMPARABLE",
                               "TEST_RUN_SUMMARY": "DIFFERENT"})
        for c in ec.compare_revisions(rows[:2], rows[2:]):
            self.assertEqual(c["interpretation"], "DESCRIPTIVE_ONLY_NOT_A_PROMOTION_DECISION")

    def test_app_failure_state_when_dependency_unavailable(self):
        tree = ast.parse(read("streamlit_app.py"))
        src = read("streamlit_app.py")
        self.assertIn("from snowflake.snowpark.context import get_active_session", src)
        self.assertIn('"SNOWFLAKE_DEPENDENCY_UNAVAILABLE"', src)
        self.assertIn('"NO_ACTIVE_SNOWFLAKE_SESSION"', src)
        idx = src.index("if SESSION is None:")
        tail = src[idx:idx + 400]
        self.assertIn("st.error(", tail)
        self.assertIn("st.stop()", tail)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("cache_data", "cache_resource", "experimental_memo",
                                             "connection", "secrets", "session_state"))
            if isinstance(node, ast.keyword):
                self.assertNotEqual(node.arg, "unsafe_allow_html")
        for bad in ("st.components", "components.v1", "st.html", "st.markdown", "st.write(", "Session.builder",
                    "os.environ", "requests", "urllib"):
            self.assertNotIn(bad, src, bad)


class X_SqlStaticChecks(unittest.TestCase):
    def test_guard_line_and_no_destructive_or_broad_statements(self):
        for name in ("schema.sql", "reader_grants.sql"):
            text = read(name)
            self.assertTrue(text.startswith("<<DEPLOYMENT_APPROVAL_REF_REQUIRED>>\n"), name)
            active = sql_statements(name).upper()
            for bad in ("OR REPLACE", "IF NOT EXISTS", "DROP ", "DELETE", "TRUNCATE",
                        "UPDATE", "FUTURE", "GRANT ALL", "ON ALL", "ROLE PUBLIC", "WITH GRANT OPTION",
                        "ACCOUNTADMIN", "CREATE WAREHOUSE", "ALTER WAREHOUSE",
                        "RESUME", "CORTEX", "EXTERNAL ACCESS", "INTEGRATION",
                        "CREATE USER", "PASSWORD", "ERROR_LOGGING", "EMBED"):
                pat = r"(?<![A-Z_])%s(?![A-Z_])" % re.escape(bad.strip())
                self.assertNotRegex(active, pat, (name, bad))

    def test_managed_access_and_named_owner(self):
        active = sql_statements("schema.sql")
        self.assertEqual(active.count("WITH MANAGED ACCESS"), 2)
        # v4: roles and warehouse are owner-created (kit SNOWSIGHT_SETUP.sql D0); the database is created by
        # SZL_EE_SETUP, and no pilot role joins the SYSADMIN hierarchy.
        self.assertIn("USE ROLE SZL_EE_SETUP;", active)
        self.assertLess(active.index("USE ROLE SZL_EE_SETUP;"), active.index("CREATE DATABASE"))
        for gone in ("USE ROLE USERADMIN", "USE ROLE SYSADMIN", "CREATE ROLE", "GRANT ROLE", "TO ROLE SYSADMIN",
                     "ON WAREHOUSE"):
            self.assertNotIn(gone, active.upper(), gone)
        self.assertIn("GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_OWNER", active)
        self.assertLess(active.index("USE ROLE SZL_EE_OWNER;"), active.index("CREATE SCHEMA"))
        self.assertLess(active.index("USE ROLE SZL_EE_OWNER;"), active.index("CREATE TABLE"))

    def test_seven_tables_with_enums_matching_core(self):
        active = sql_statements("schema.sql")
        tables = re.findall(r"CREATE TABLE SZL_EE_DB\.EE_DATA\.([A-Z_]+) \(", active)
        self.assertEqual(sorted(tables), sorted(["ASSETS", "REVISIONS", "OBSERVATIONS",
                                                 "RIGHTS_RECORDS", "INGESTION_BATCHES",
                                                 "EXCLUSIONS", "REJECTED_ROWS"]))
        self.assertNotRegex(active, r"PRIMARY KEY|UNIQUE|FOREIGN KEY|REFERENCES")
        pairs = {"PROVIDER": ec.PROVIDERS, "VISIBILITY_CLASS": ec.VISIBILITY_CLASSES,
                 "DISPOSITION": ec.DISPOSITIONS, "EVIDENCE_CLASS": ec.EVIDENCE_CLASSES,
                 "OBSERVATION_TYPE": ec.OBSERVATION_TYPES, "VALUE_STATE": ec.VALUE_STATES,
                 "ALLOWED_USE": ec.ALLOWED_USES,
                 "REDISTRIBUTION_STATUS": ec.REDISTRIBUTION_STATUSES,
                 "STATUS": ec.BATCH_STATUSES, "EXCLUSION_REASON": ec.EXCLUSION_REASONS,
                 "SCOPE": ec.EXCLUSION_SCOPES, "REASON_CODE": ec.REASON_CODES,
                 "CONTENT_DIGEST_ALGORITHM": ec.DIGEST_ALGORITHMS}
        for col, values in pairs.items():
            m = re.search(r"CHECK \(%s IN \(([^)]*)\)\)" % col, active)
            self.assertIsNotNone(m, col)
            self.assertEqual(tuple(v.strip().strip("'") for v in m.group(1).split(",")),
                             tuple(values), col)

    def test_column_lengths_cover_python_grammar(self):
        active = sql_statements("schema.sql")
        need = {"ASSET_ID": 64, "REVISION_ID": 64, "OBSERVATION_ID": 64,
                "CANONICAL_LOCATOR": len("https://huggingface.co/") + 199,
                "SOURCE_LOCATOR": len("https://huggingface.co/") + 199,
                "IMMUTABLE_SOURCE_REVISION": len("git-sha256:") + 64,
                "CONTENT_DIGEST": 64, "SUMMARIZED_VALUE": 64, "OWNER_REFERENCE": 80,
                "LICENSE_REFERENCE": 80, "SOURCE_IDENTIFIER": 200,
                "DATA_LABEL": len(ec.SYNTHETIC_LABEL), "ERROR_SUMMARY": 256,
                "SOURCE_REVISION": 80, "FIELD_NAME": 64,
                "REASON_CODE": max(len(r) for r in ec.REASON_CODES),
                "DISPOSITION": max(len(d) for d in ec.DISPOSITIONS),
                "ALLOWED_USE": max(len(d) for d in ec.ALLOWED_USES)}
        for col, n in need.items():
            for m in re.finditer(r"^\s+%s VARCHAR\((\d+)\)" % col, active, re.M):
                self.assertGreaterEqual(int(m.group(1)), n, col)
                self.assertLessEqual(int(m.group(1)), 256, col)

    def test_training_default_false_and_utc_types(self):
        active = sql_statements("schema.sql")
        self.assertIn("TRAINING_ALLOWED BOOLEAN NOT NULL DEFAULT FALSE", active)
        self.assertIn("CHECK (TRAINING_ALLOWED = FALSE OR TRAINING_EVIDENCE_REF IS NOT NULL)",
                      active)
        self.assertNotRegex(active, r"TIMESTAMP_(NTZ|LTZ)|\bTIMESTAMP\b(?!_TZ)")
        self.assertEqual(len(re.findall(r"_UTC TIMESTAMP_TZ\(6\)", active)), 7)
        self.assertNotIn("VARIANT", active)
        self.assertNotRegex(active, r"VARCHAR\s*(,|\n| NOT)")

    def test_grants_are_least_privilege(self):
        active = sql_statements("schema.sql")
        for line in re.findall(r"^GRANT .*$", active, re.M):
            if "TO ROLE SZL_EE_APP" in line and " ON TABLE " in line:
                self.assertTrue(line.startswith("GRANT SELECT ON TABLE"), line)
            if "TO ROLE SZL_EE_INGEST" in line and " ON TABLE " in line:
                self.assertTrue(line.startswith("GRANT SELECT, INSERT ON TABLE"), line)
            self.assertNotIn("SZL_EE_VIEWER", line)
        reader = sql_statements("reader_grants.sql")
        grants = re.findall(r"^GRANT .*;$", reader, re.M)
        self.assertEqual(grants, [
            "GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_VIEWER;",
            "GRANT USAGE ON SCHEMA SZL_EE_DB.EE_APP TO ROLE SZL_EE_VIEWER;",
            "GRANT USAGE ON STREAMLIT SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER TO ROLE SZL_EE_VIEWER;"])
        self.assertNotIn("WAREHOUSE", reader)
        self.assertNotIn("EE_DATA", reader)

    def test_core_default_schema_matches_sql(self):
        self.assertEqual(ec.DEFAULT_DATA_SCHEMA, "SZL_EE_DB.EE_DATA")
        self.assertIn("CREATE SCHEMA SZL_EE_DB.EE_DATA", sql_statements("schema.sql"))


class OfflineBoundary(unittest.TestCase):
    def test_inherited_environment_is_not_a_live_switch(self):
        env = {name: "synthetic" for name in itest.REQUIRED_ENV}
        self.assertEqual(itest.classify_launch(["-v"], env), "offline")
        self.assertEqual(itest.classify_launch(["--live-approved", "-v"], env), "live")
        self.assertEqual(itest.classify_launch(["--live-approved"], {}), "not_configured")
        self.assertNotIn("--live-approved", rle.integration_argv(sys.executable))

    def test_runner_integration_env_drops_live_switches(self):
        saved = {}
        keys = ("SZL_EE_INTEGRATION_APPROVAL_REF", "SNOWFLAKE_ACCOUNT",
                "SZL_EE_SNOWFLAKE_CONNECTION_NAME")
        for key in keys:
            saved[key] = os.environ.get(key)
            os.environ[key] = "do-not-forward"
        try:
            env = rle.integration_child_env(tempfile.mkdtemp())
        finally:
            for key, old in saved.items():
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old
        for key in keys:
            self.assertNotIn(key, env)
        self.assertEqual(env["SNOWFLAKE_HOME"], env["HOME"])

    def test_failed_identity_refuses_merge(self):
        calls = []

        def boom(*_a, **_k):
            calls.append("merge")
            raise AssertionError("MERGE executed")

        old = itest.ec.build_merge
        previous = itest.IDENTITY_OK
        try:
            itest.ec.build_merge = boom
            itest.IDENTITY_OK = False
            with self.assertRaises(RuntimeError) as caught:
                itest.load_fixture()
            self.assertIn("MERGE not executed", str(caught.exception))
            self.assertEqual(calls, [])
        finally:
            itest.ec.build_merge = old
            itest.IDENTITY_OK = previous

    def test_admin_role_fails_identity_before_any_write(self):
        digest = hashlib.sha256(b"ZZ99999").hexdigest()
        env = {"SZL_EE_EXPECTED_ACCOUNT_SHA256": digest, "SZL_EE_EXPECTED_WAREHOUSE": "SZL_EE_WH"}
        row = {"A": "zz99999", "D": "SZL_EE_DB", "S": "EE_DATA", "W": "SZL_EE_WH",
               "R": "ACCOUNTADMIN"}
        self.assertFalse(itest.identity_matches(row, env))
        row["R"] = "SZL_EE_INGEST"
        self.assertTrue(itest.identity_matches(row, env))

    def test_failures_outrank_skips(self):
        class Failed:
            failures = [object()]
            errors = []
            skipped = [object(), object(), object(), object()]

            def wasSuccessful(self):
                return False

        class CleanSkip:
            failures = []
            errors = []
            skipped = [object()]

            def wasSuccessful(self):
                return True

        self.assertEqual(itest.integration_process_code(Failed()), 1)
        self.assertEqual(itest.integration_process_code(CleanSkip()), 3)
        dirty = {"not_run": 4, "failures": 1, "errors": 0, "skipped": 4, "ran": 11,
                 "result": "FAILED"}
        self.assertEqual(rle.decide("integration_snowflake", 1, dirty), "FAIL")
        self.assertEqual(rle.decide("integration_snowflake", 3, dirty), "FAIL")
        clean = {"not_run": 11, "failures": 0, "errors": 0, "skipped": 11, "ran": 11,
                 "result": "OK"}
        self.assertEqual(rle.decide("integration_snowflake", 3, clean), "NOT_RUN")


if __name__ == "__main__":
    unittest.main()
