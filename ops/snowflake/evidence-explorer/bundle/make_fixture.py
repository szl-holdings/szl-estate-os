"""Deterministic synthetic fixture for the SZL Evidence Explorer (pilot 1).

SYNTHETIC DEMONSTRATION DATA - NOT PRODUCTION OR MODEL QUALIFICATION.
All names are mock://... locators for illustrative assets. All values are
illustrative and make no claim about any real SZL artifact or its performance.
The one real identifier is the preserved Studio blob exclusion
f75070d94bc3683a7aa18e3d111cb0dd112638c1, used only as an exclusion key.

Usage:  python -I -B make_fixture.py [output_path]   (default fixture_v1.json)
Stdlib only, fixed seed, no network, no clock reads.
"""
import hashlib
import json
import os
import random
import sys

SEED = 20261021
AS_OF = "2026-10-21T00:00:00Z"
LABEL = ("SYNTHETIC DEMONSTRATION DATA \u2014 NOT PRODUCTION OR MODEL "
         "QUALIFICATION.")
STUDIO_BLOB = "f75070d94bc3683a7aa18e3d111cb0dd112638c1"


def build():
    rng = random.Random(SEED)

    def hx(n):
        return "".join(rng.choice("0123456789abcdef") for _ in range(n))

    def syn(d):
        d["is_synthetic"] = True
        d["data_label"] = LABEL
        return d

    def asset(aid, prov, loc, vis, disp):
        return syn({"asset_id": aid, "provider": prov, "canonical_locator": loc,
                    "owner_reference": "mock-owner:demo-team",
                    "visibility_class": vis, "disposition": disp})

    content = {}

    def rev(rid, aid, srev, ts, loc, corrupt=False):
        body = ("SYNTHETIC CONTENT %s seed %d nonce %s" % (rid, SEED, hx(12))).encode()
        content[rid] = body
        digest = hashlib.sha256(body + (b"-tampered" if corrupt else b"")).hexdigest()
        return syn({"revision_id": rid, "asset_id": aid,
                    "immutable_source_revision": srev, "observed_at_utc": ts,
                    "source_locator": loc, "content_digest_algorithm": "sha256",
                    "content_digest": digest})

    def obs(oid, rid, ecls, otype, ts, loc, state, value):
        return syn({"observation_id": oid, "revision_id": rid, "evidence_class": ecls,
                    "observation_type": otype, "observed_at_utc": ts,
                    "source_locator": loc, "value_state": state,
                    "summarized_value": value})

    def rights(rr, loc, lic, use, redis, ts, train=False, ev=None):
        return syn({"rights_record_id": rr, "source_locator": loc,
                    "license_reference": lic, "allowed_use": use,
                    "redistribution_status": redis, "training_allowed": train,
                    "training_evidence_ref": ev, "reviewed_at_utc": ts})

    KIT = "mock://github/demo-org/evidence-kit-demo"
    VER = "mock://github/demo-org/receipt-verifier-demo"
    ADV = "mock://huggingface/demo-org/advisory-model-demo"
    TEL = "mock://huggingface/demo-org/telemetry-dataset-demo"
    PRB = "mock://runtime/demo-host/health-probe-demo"
    STU = "mock://github/demo-org/studio-copy-demo"
    DEN = "mock://huggingface/demo-org/denied-corpus-demo"
    FOR = "mock://github/demo-org/scraped-forum-demo"

    exclusions = [
        {"source_identifier": STUDIO_BLOB, "exclusion_reason": "OWNER_EXCLUSION",
         "effective_at_utc": "2026-10-01T00:00:00Z", "scope": "ALL"},
        {"source_identifier": FOR, "exclusion_reason": "OUT_OF_SCOPE",
         "effective_at_utc": "2026-10-01T00:00:00Z", "scope": "ALL"},
    ]
    rights_rows = [
        rights("demo-rr-kit", KIT, "SPDX:Apache-2.0", "METADATA_DISPLAY", "ALLOWED",
               "2026-09-01T00:00:00Z"),
        rights("demo-rr-verifier", VER, "SPDX:MIT", "METADATA_DISPLAY", "ALLOWED",
               "2026-04-01T00:00:00Z"),
        rights("demo-rr-advisory", ADV, "SPDX:Apache-2.0", "METADATA_DISPLAY",
               "ALLOWED", "2026-10-01T00:00:00Z"),
        rights("demo-rr-telemetry", TEL, "LicenseRef:demo-restricted",
               "METADATA_INTERNAL", "PROHIBITED", "2026-10-01T00:00:00Z"),
        rights("demo-rr-denied", DEN, "LicenseRef:demo-denied", "NONE",
               "PROHIBITED", "2026-10-01T00:00:00Z"),
        # malformed: training allowed without evidence -> INCONSISTENT_FIELDS
        rights("demo-rr-bad-training", KIT, "SPDX:Apache-2.0", "METADATA_DISPLAY",
               "ALLOWED", "2026-10-02T00:00:00Z", train=True, ev=None),
    ]
    assets = [
        asset("demo-gh-evidence-kit", "GITHUB", KIT, "PUBLIC", "PILOT_ADAPTER"),
        asset("demo-gh-receipt-verifier", "GITHUB", VER, "PUBLIC",
              "INGEST_APPROVED_METADATA"),
        asset("demo-hf-advisory-model", "HUGGINGFACE", ADV, "PUBLIC", "KEEP_CANONICAL"),
        asset("demo-hf-telemetry-dataset", "HUGGINGFACE", TEL, "RESTRICTED",
              "INGEST_APPROVED_METADATA"),
        asset("demo-rt-health-probe", "RUNTIME", PRB, "PRIVATE", "PILOT_ADAPTER"),
        asset("demo-gh-studio-copy", "GITHUB", STU, "UNKNOWN", "EXCLUDED"),
        asset("demo-hf-denied-corpus", "HUGGINGFACE", DEN, "RESTRICTED", "BLOCKED"),
        asset("demo-gh-scraped-forum", "GITHUB", FOR, "UNKNOWN", "EXCLUDED"),  # EXCLUDED
        asset("demo-gl-other-forge", "GITLAB", "mock://github/demo-org/other-forge-demo",
              "PUBLIC", "UNKNOWN"),  # ENUM_VIOLATION
    ]
    revisions = [
        rev("demo-rev-kit-a", "demo-gh-evidence-kit", "git-sha1:" + hx(40),
            "2026-09-01T12:00:00Z", KIT + "/tree/rev-a"),
        rev("demo-rev-verifier-a", "demo-gh-receipt-verifier", "git-sha256:" + hx(64),
            "2026-04-02T09:30:00Z", VER + "/tree/rev-a"),
        rev("demo-rev-advisory-a", "demo-hf-advisory-model", "hf-commit:" + hx(40),
            "2026-10-05T08:00:00Z", ADV + "/blob/rev-a/README.md"),
        rev("demo-rev-telemetry-a", "demo-hf-telemetry-dataset", "hf-commit:" + hx(40),
            "2026-10-06T08:00:00Z", TEL + "/blob/rev-a/README.md"),
        rev("demo-rev-probe-a", "demo-rt-health-probe", "runtime-build:" + hx(16),
            "2026-10-18T06:00:00.250000Z", PRB + "/build/rev-a"),
        rev("demo-rev-denied-a", "demo-hf-denied-corpus", "hf-commit:" + hx(40),
            "2026-10-06T08:00:00Z", DEN + "/blob/rev-a/README.md"),
        # rejected revisions
        rev("demo-rev-studio-copy", "demo-gh-studio-copy", "git-sha1:" + STUDIO_BLOB,
            "2026-10-01T00:00:00Z", STU + "/blob/rev-a"),          # EXCLUDED
        rev("demo-rev-kit-mutable", "demo-gh-evidence-kit", "main",
            "2026-09-02T00:00:00Z", KIT + "/tree/main"),           # MALFORMED_REVISION
        rev("demo-rev-advisory-bad", "demo-hf-advisory-model", "hf-commit:" + hx(40),
            "2026-10-07T00:00:00Z", ADV + "/blob/rev-x/README.md",
            corrupt=True),                                         # CONTENT_DIGEST_MISMATCH
        rev("demo-rev-probe-wrong", "demo-rt-health-probe", "git-sha1:" + hx(40),
            "2026-10-18T07:00:00Z", PRB + "/build/rev-x"),         # MALFORMED_REVISION
    ]
    M, R, U = "MEASURED", "REPORTED", "UNKNOWN"
    S, TR, CF, RP, CK = ("ILLUSTRATIVE_SCORE", "TEST_RUN_SUMMARY", "CARD_FIELD",
                         "RUNTIME_PROBE", "CHECKSUM_RECORD")
    observations = [
        obs("demo-obs-kit-a-score", "demo-rev-kit-a", M, S, "2026-09-01T12:05:00Z",
            KIT + "/tree/rev-a/eval", "PRESENT", "0.71 (illustrative)"),
        obs("demo-obs-kit-a-tests", "demo-rev-kit-a", M, TR, "2026-09-01T12:06:00Z",
            KIT + "/tree/rev-a/tests", "PRESENT", "41/44 synthetic checks passed"),
        obs("demo-obs-kit-a-card", "demo-rev-kit-a", R, CF, "2026-09-01T12:07:00Z",
            KIT + "/tree/rev-a/README.md", "PRESENT", "license field present"),
        obs("demo-obs-kit-a-checksum", "demo-rev-kit-a", M, CK, "2026-09-01T12:08:00Z",
            KIT + "/tree/rev-a/SHA256SUMS", "PRESENT", "sha256 recorded"),
        obs("demo-obs-kit-a-probe", "demo-rev-kit-a", M, RP, "2026-09-01T12:09:00Z",
            KIT + "/tree/rev-a/probe", "PRESENT", "status=ok (illustrative)"),
        obs("demo-obs-ver-a-score", "demo-rev-verifier-a", R, S, "2026-04-02T09:31:00Z",
            VER + "/tree/rev-a/eval", "PRESENT", "0.55 (illustrative)"),
        obs("demo-obs-ver-a-tests", "demo-rev-verifier-a", M, TR, "2026-04-02T09:32:00Z",
            VER + "/tree/rev-a/tests", "PRESENT", "12/12 synthetic checks passed"),
        obs("demo-obs-ver-a-card", "demo-rev-verifier-a", U, CF, "2026-04-02T09:33:00Z",
            VER + "/tree/rev-a/README.md", "MISSING", None),
        obs("demo-obs-adv-score", "demo-rev-advisory-a", U, S, "2026-10-05T08:01:00Z",
            ADV + "/blob/rev-a/eval.json", "MISSING", None),
        obs("demo-obs-adv-card", "demo-rev-advisory-a", R, CF, "2026-10-05T08:02:00Z",
            ADV + "/blob/rev-a/README.md", "PRESENT", "intended use stated"),
        obs("demo-obs-adv-tests", "demo-rev-advisory-a", M, TR, "2026-10-05T08:03:00Z",
            ADV + "/blob/rev-a/tests", "PRESENT", "9/10 synthetic checks passed"),
        obs("demo-obs-adv-checksum", "demo-rev-advisory-a", M, CK, "2026-10-05T08:04:00Z",
            ADV + "/blob/rev-a/SHA256SUMS", "PRESENT", "sha256 recorded"),
        obs("demo-obs-tel-card", "demo-rev-telemetry-a", R, CF, "2026-10-06T08:01:00Z",
            TEL + "/blob/rev-a/README.md", "PRESENT", "row count 5000 (illustrative)"),
        obs("demo-obs-tel-checksum", "demo-rev-telemetry-a", M, CK, "2026-10-06T08:02:00Z",
            TEL + "/blob/rev-a/SHA256SUMS", "PRESENT", "sha256 recorded"),
        obs("demo-obs-prb-probe", "demo-rev-probe-a", M, RP, "2026-10-18T06:01:00Z",
            PRB + "/build/rev-a/probe", "PRESENT", "status=ok (illustrative)"),
        obs("demo-obs-prb-score", "demo-rev-probe-a", U, S, "2026-10-18T06:02:00Z",
            PRB + "/build/rev-a/eval", "NOT_MEASURED", None),
        obs("demo-obs-prb-tests", "demo-rev-probe-a", M, TR, "2026-10-18T06:03:00Z",
            PRB + "/build/rev-a/tests", "PRESENT", "3/3 synthetic probes passed"),
    ]
    bad = []
    b = obs("demo-obs-bad-date", "demo-rev-kit-a", M, S, "2026-02-30T00:00:00Z",
            KIT + "/x", "PRESENT", "0.1 (illustrative)"); bad.append(b)
    b = obs("demo-obs-bad-offset", "demo-rev-advisory-a", M, S, "2026-10-01T10:00:00+02:00",
            ADV + "/x", "PRESENT", "0.1 (illustrative)"); bad.append(b)
    b = obs("demo-obs-bad-future", "demo-rev-probe-a", M, RP, "2027-01-01T00:00:00Z",
            PRB + "/x", "PRESENT", "status=ok (illustrative)"); bad.append(b)
    b = obs("demo-obs-bad-secret-field", "demo-rev-kit-a", M, S, "2026-09-01T13:00:00Z",
            KIT + "/x", "PRESENT", "0.1 (illustrative)")
    b["api_token"] = "synthetic-placeholder-not-a-token"; bad.append(b)
    b = obs("demo-obs-bad-secret-value", "demo-rev-kit-a", M, S, "2026-09-01T13:01:00Z",
            KIT + "/x", "PRESENT", "ghp_SYNTHETICDEMONOTREAL"); bad.append(b)
    b = obs("demo-obs-bad-enum", "demo-rev-kit-a", "VERIFIED", S, "2026-09-01T13:02:00Z",
            KIT + "/x", "PRESENT", "0.1 (illustrative)"); bad.append(b)
    b = obs("demo-obs-bad-missing", "demo-rev-kit-a", M, S, "2026-09-01T13:03:00Z",
            KIT + "/x", "PRESENT", "0.1 (illustrative)")
    del b["source_locator"]; bad.append(b)
    bad.append(obs("demo-obs-bad-orphan-mutable", "demo-rev-kit-mutable", M, S,
                   "2026-09-02T00:01:00Z", KIT + "/x", "PRESENT", "0.1 (illustrative)"))
    bad.append(obs("demo-obs-bad-orphan-studio", "demo-rev-studio-copy", M, CK,
                   "2026-10-01T00:01:00Z", STU + "/x", "PRESENT", "sha256 recorded"))
    b = obs("demo-obs-bad-not-synthetic", "demo-rev-kit-a", M, S, "2026-09-01T13:04:00Z",
            KIT + "/x", "PRESENT", "0.1 (illustrative)")
    b["is_synthetic"] = False; bad.append(b)
    bad.append(obs("demo-obs-bad-inconsistent", "demo-rev-kit-a", M, S,
                   "2026-09-01T13:05:00Z", KIT + "/x", "MISSING", "0.1 (illustrative)"))
    bad.append(obs("demo-obs-den-card", "demo-rev-denied-a", R, CF, "2026-10-06T08:03:00Z",
                   DEN + "/x", "PRESENT", "row count 10 (illustrative)"))  # RIGHTS_DENIED
    b = obs("demo-obs-bad-type", "demo-rev-kit-a", M, S, "2026-09-01T13:06:00Z",
            KIT + "/x", "PRESENT", None)
    b["summarized_value"] = 0.9; bad.append(b)
    b = dict(observations[0]); b["summarized_value"] = "0.99 (illustrative)"
    bad.append(b)                                   # CONFLICTING_DUPLICATE_ID
    bad.append(dict(observations[1]))               # identical duplicate -> skipped

    batch1 = {"source_revision": "fixture-v1-batch-1",
              "tables": {"EXCLUSIONS": exclusions, "RIGHTS_RECORDS": rights_rows,
                         "ASSETS": assets, "REVISIONS": revisions,
                         "OBSERVATIONS": observations + bad}}
    content1 = {k: v.decode() for k, v in content.items()}

    content.clear()
    rev_b = rev("demo-rev-kit-b", "demo-gh-evidence-kit", "git-sha1:" + hx(40),
                "2026-10-15T10:00:00Z", KIT + "/tree/rev-b")
    obs_b = [
        obs("demo-obs-kit-b-score", "demo-rev-kit-b", M, S, "2026-10-15T10:05:00Z",
            KIT + "/tree/rev-b/eval", "PRESENT", "0.74 (illustrative)"),
        obs("demo-obs-kit-b-tests", "demo-rev-kit-b", M, TR, "2026-10-15T10:06:00Z",
            KIT + "/tree/rev-b/tests", "PRESENT", "44/44 synthetic checks passed"),
        obs("demo-obs-kit-b-card", "demo-rev-kit-b", R, CF, "2026-10-15T10:07:00Z",
            KIT + "/tree/rev-b/README.md", "PRESENT", "license field present"),
        obs("demo-obs-kit-b-probe", "demo-rev-kit-b", U, RP, "2026-10-15T10:08:00Z",
            KIT + "/tree/rev-b/probe", "NOT_MEASURED", None),
    ]
    batch2 = {"source_revision": "fixture-v1-batch-2",
              "tables": {"ASSETS": [dict(assets[0])],        # identical -> skipped
                         "REVISIONS": [rev_b], "OBSERVATIONS": obs_b}}
    content2 = {k: v.decode() for k, v in content.items()}
    batch3 = {"source_revision": "fixture-v1-batch-3",
              "tables": {"EXCLUSIONS": [
                  {"source_identifier": "demo-obs-adv-card",
                   "exclusion_reason": "OWNER_EXCLUSION",
                   "effective_at_utc": "2026-10-20T00:00:00Z", "scope": "DISPLAY"}]}}
    return {"fixture_version": "szl-ee-fixture/v1", "seed": SEED, "as_of_utc": AS_OF,
            "label": LABEL, "is_synthetic": True,
            "batches": [{"payload": batch1, "local_content": content1},
                        {"payload": batch2, "local_content": content2},
                        {"payload": batch3, "local_content": {}}]}


def render(fixture):
    return (json.dumps(fixture, sort_keys=True, indent=1, ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def load(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "fixture_v1.json"
    data = render(build())
    with open(out, "wb") as fh:
        fh.write(data)
    sys.stdout.write("%s %d bytes sha256=%s\n"
                     % (os.path.basename(out), len(data), hashlib.sha256(data).hexdigest()))
