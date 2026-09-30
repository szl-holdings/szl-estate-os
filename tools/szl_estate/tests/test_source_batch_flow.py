"""Tiny synthetic main wiring: transport is injected, candidate code is never run."""

import base64
import hashlib
import json

import pytest

from szl_estate import source_batch as sb
from szl_estate.content_review import ReviewReceipt, git_blob_sha1
from szl_estate.storage import sha256_digest


NOW = "2026-09-30T12:00:00Z"
COMMIT = "a" * 40
REPOSITORY = "szl-holdings/audit"
RAW = b"# ordinary pinned source, read as data only\n"


@pytest.fixture
def flow(tmp_path, monkeypatch):
    """One regular root blob, exact index/plan hashes, and an inert existing file."""
    executable = tmp_path / "gh.exe"
    executable.write_bytes(b"inert fixture: never executed")
    blob = git_blob_sha1(RAW)
    tree_body = b"100644 README.md\0" + bytes.fromhex(blob)
    tree = hashlib.sha1(b"tree " + str(len(tree_body)).encode("ascii") + b"\0" + tree_body).hexdigest()
    row = {"repository_id": REPOSITORY, "snapshot_sha": COMMIT, "path": "README.md",
           "git_object_sha": blob, "size_bytes": len(RAW), "entry_type": "blob",
           "unread": True, "historical_inspection_status": "unread", "epistemic_status": "PROPOSAL"}
    index = tmp_path / "github_files.jsonl"
    index_bytes = json.dumps(row, sort_keys=True).encode("utf-8") + b"\n"
    index.write_bytes(index_bytes)
    plan = tmp_path / "plan.json"
    plan_data = {"state": {"github": {"batch": [row], "historically_inspected_paths": 542},
                           "artifacts": {"github_files.jsonl": {"sha256": hashlib.sha256(index_bytes).hexdigest()}}}}
    plan_bytes = json.dumps(plan_data, sort_keys=True).encode("utf-8") + b"\n"
    plan.write_bytes(plan_bytes)
    out = tmp_path / "result"
    endpoints = [f"repos/{REPOSITORY}", f"repos/{REPOSITORY}/git/commits/{COMMIT}",
                 f"repos/{REPOSITORY}/git/trees/{tree}", f"repos/{REPOSITORY}/git/blobs/{blob}"]
    bodies = {
        endpoints[0]: {"full_name": REPOSITORY, "private": False, "visibility": "public"},
        endpoints[1]: {"sha": COMMIT, "tree": {"sha": tree}},
        endpoints[2]: {"sha": tree, "truncated": False,
                       "tree": [{"path": "README.md", "mode": "100644", "type": "blob", "sha": blob, "size": len(RAW)}]},
        endpoints[3]: {"sha": blob, "size": len(RAW), "encoding": "base64",
                       "content": base64.b64encode(RAW).decode("ascii")},
    }
    requests, clients = [], []

    class FakeGitHubRead:
        def __init__(self, approved_executable, working_directory):
            assert approved_executable == executable and working_directory == out.parent
            self.calls = self.tree_calls = 0
            clients.append(self)

        def request(self, endpoint, *, retry=True):
            assert endpoint in bodies, "unexpected fixture endpoint"
            self.calls += 1
            self.tree_calls += int("/git/trees/" in endpoint)
            requests.append(endpoint)
            return bodies[endpoint], {"endpoint": "https://api.github.com/" + endpoint,
                                      "http_status": 200, "observed_at_utc": NOW}

    monkeypatch.setattr(sb, "GitHubRead", FakeGitHubRead)
    monkeypatch.setattr(sb, "utc", lambda: NOW)
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("flow must not launch subprocesses"))
    argv = ["--plan", str(plan), "--expected-plan-sha256", hashlib.sha256(plan_bytes).hexdigest(),
            "--file-index", str(index), "--out", str(out), "--gh-executable", str(executable),
            "--source-base-commit", "b" * 40]
    return {"argv": argv, "plan": plan, "plan_bytes": plan_bytes, "index": index,
            "index_bytes": index_bytes, "out": out, "endpoints": endpoints,
            "bodies": bodies, "requests": requests, "clients": clients}


def execution(flow):
    envelope = json.loads((flow["out"] / "execution.json").read_text(encoding="utf-8"))
    assert envelope["sha256"] == sha256_digest(envelope["payload"])
    return envelope["payload"]


def test_main_pinned_public_commit_tree_blob_credits_bytes_static_and_runtime_pending(flow, capsys):
    assert sb.main(flow["argv"]) == 1
    assert flow["requests"] == flow["endpoints"]
    payload = execution(flow)
    assert payload["api_requests"] == 4 and payload["tree_requests"] == 1
    assert payload["unique_fetched_objects"] == 1 and payload["unique_fetched_bytes"] == len(RAW)
    assert payload["failures"] == []
    assert payload["coverage"]["newly_verified_read_paths"] == 1
    assert payload["coverage"]["indexed_completed_paths"] == 1
    assert payload["coverage"]["reconciled_read_total"] == 543
    document, = payload["documents"]
    assert document["receipt"]["byte_read_status"] == "COMPLETE"
    assert document["receipt"]["static_contract_status"] == "SKIPPED"
    assert document["static_review_pending"] is True
    assert document["receipt"]["runtime_status"] == payload["runtime_status"] == "NOT_RUN"
    assert payload["source_execution_performed"] is False and payload["estate_ready"] is False
    cache_bytes = (flow["out"] / "cache" / document["cache_name"]).read_bytes()
    assert cache_bytes == RAW
    cached = ReviewReceipt.from_dict(document["receipt"], cached_text=cache_bytes.decode("utf-8"))
    assert cached.byte_coverage_credit and not cached.fresh_source_proof
    assert flow["plan"].read_bytes() == flow["plan_bytes"]
    assert flow["index"].read_bytes() == flow["index_bytes"]
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "PARTIAL" and summary["runtime_status"] == "NOT_RUN"
    assert summary["estate_ready"] is False


@pytest.mark.parametrize("metadata", [
    {"full_name": REPOSITORY, "private": True, "visibility": "private"},
    {"full_name": REPOSITORY, "visibility": "public"},
    {"full_name": REPOSITORY, "private": False},
    {"full_name": REPOSITORY, "private": False, "visibility": "private"},
])
def test_private_unknown_or_contradictory_visibility_stops_before_commit_tree_blob(flow, metadata, capsys):
    flow["bodies"][flow["endpoints"][0]] = metadata
    assert sb.main(flow["argv"]) == 1
    assert flow["requests"] == flow["endpoints"][:1]
    payload = execution(flow)
    assert payload["failures"][0]["code"] == "PUBLIC_VISIBILITY_NOT_ESTABLISHED"
    assert payload["coverage"]["newly_verified_read_paths"] == 0
    assert payload["coverage"]["indexed_completed_paths"] == 0
    assert payload["unique_fetched_objects"] == payload["unique_fetched_bytes"] == 0
    document, = payload["documents"]
    assert document["receipt"]["byte_read_status"] == "ERROR" and document["cache_name"] is None
    assert list((flow["out"] / "cache").iterdir()) == []
    assert not payload["estate_ready"] and payload["runtime_status"] == "NOT_RUN"
    assert json.loads(capsys.readouterr().out)["coverage"]["indexed_completed_paths"] == 0


def test_truncated_tree_never_fetches_blob_or_credits_read(flow, capsys):
    flow["bodies"][flow["endpoints"][2]]["truncated"] = True
    assert sb.main(flow["argv"]) == 1
    assert flow["requests"] == flow["endpoints"][:3]
    payload = execution(flow)
    assert payload["failures"][0]["code"] == "TRUNCATED_OR_UNPINNED_TREE"
    assert payload["coverage"]["newly_verified_read_paths"] == 0
    assert payload["coverage"]["indexed_completed_paths"] == 0
    assert payload["documents"][0]["cache_name"] is None
    assert payload["unique_fetched_objects"] == 0
    assert json.loads(capsys.readouterr().out)["estate_ready"] is False


@pytest.mark.parametrize("changed", ["plan", "index"])
def test_plan_and_index_hash_binding_stop_before_transport_or_output(flow, changed):
    flow[changed].write_bytes(flow[changed].read_bytes() + b" ")
    expected = SystemExit if changed == "plan" else sb.ReadError
    code = "PLAN_CHANGED" if changed == "plan" else "FILE_INDEX_CHANGED"
    with pytest.raises(expected, match="^" + code + "$"):
        sb.main(flow["argv"])
    assert flow["clients"] == [] and flow["requests"] == []
    assert not flow["out"].exists()


def test_existing_output_preserves_partial_files_and_never_starts_transport(flow):
    flow["out"].mkdir()
    partial = flow["out"] / "progress.json"
    partial.write_bytes(b"partially written receipt: preserve exact bytes")
    with pytest.raises(sb.ReadError, match="^EXISTING_OR_PROTECTED_OUTPUT_PRESERVED$"):
        sb.main(flow["argv"])
    assert partial.read_bytes() == b"partially written receipt: preserve exact bytes"
    assert list(flow["out"].iterdir()) == [partial]
    assert flow["clients"] == [] and flow["requests"] == []
