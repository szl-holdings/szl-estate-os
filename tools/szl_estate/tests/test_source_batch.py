"""Synthetic transport/tree/source plan tests. No source repository code runs."""
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from szl_estate import source_batch as sb


def tree_oid(raw):
    return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def test_empty_git_tree_has_known_object_hash():
    assert sb.verify_tree([], "4b825dc642cb6eb9a060e54bf8d69288fbee4904") == {}


def test_tree_canonical_sort_treats_directory_name_as_slash():
    entries = [{"path": "app", "mode": "040000", "sha": "a" * 40, "type": "tree"},
               {"path": "app.md", "mode": "100644", "sha": "b" * 40, "type": "blob", "size": 3}]
    raw = b"100644 app.md\0" + bytes.fromhex("b" * 40) + b"40000 app\0" + bytes.fromhex("a" * 40)
    assert set(sb.verify_tree(entries, tree_oid(raw))) == {"app", "app.md"}


@pytest.mark.parametrize("entries", [[{"path": "../escape", "mode": "100644", "sha": "a" * 40, "type": "blob"}],
    [{"path": "x", "mode": "040000", "sha": "a" * 40, "type": "blob"}],
    [{"path": "x", "mode": "100644", "sha": "x" * 40, "type": "blob"}],
    [{"path": "x", "mode": "100644", "sha": "a" * 40, "type": "blob"}] * 2,
    {"tree": []}])
def test_invalid_duplicate_tree_metadata_never_passes(entries):
    with pytest.raises(sb.ReadError):
        sb.verify_tree(entries, "a" * 40)


def test_tree_sha_mismatch_is_explicit():
    with pytest.raises(sb.ReadError, match="TREE_OBJECT_DIGEST_MISMATCH"):
        sb.verify_tree([], "a" * 40)


@pytest.mark.parametrize("raw", [b'{"sha":1,"sha":2}', b'{"value":NaN}', b'invalid', b'"\xff"'])
def test_duplicate_nonfinite_invalid_json_rejected(raw):
    with pytest.raises(sb.ReadError):
        sb.unique_json(raw)


def test_bounded_input_reads_once_and_caps_bytes(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"12345")
    assert sb.bounded_input(path, 5) == b"12345"
    with pytest.raises(sb.ReadError, match="INPUT_BYTE_BOUND"):
        sb.bounded_input(path, 4)


def test_windows_reparse_ancestor_rejected_without_symlink_privilege(tmp_path, monkeypatch):
    original = Path.lstat
    def junction(path):
        info = original(path)
        if path == tmp_path:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info
    monkeypatch.setattr(Path, "lstat", junction)
    with pytest.raises(sb.ReadError, match="REPARSE_LOCAL_PATH"):
        sb.safe_chain(tmp_path / "future-output")


class FakeProcess:
    def __init__(self, stdout, stderr=b"", returncode=0):
        self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(stderr)
        self.returncode = returncode
        self.killed = False
    def wait(self, timeout):
        return self.returncode
    def kill(self):
        self.killed = True
        self.returncode = -9


def response(status=200, body=b'{"value":1}', headers=b""):
    return f"HTTP/2.0 {status} result\n".encode() + headers + b"\n" + body


def test_only_approved_get_command_is_launched_and_headers_not_retained(tmp_path, monkeypatch):
    calls = []
    process = FakeProcess(response(headers=b"Authorization: PRIVATE-HEADER\nSet-Cookie: PRIVATE-COOKIE\n"))
    def launch(command, **kwargs):
        calls.append((command, kwargs))
        return process
    monkeypatch.setattr(sb.subprocess, "Popen", launch)
    monkeypatch.setenv("GH_DEBUG", "api")
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    value, observed = reader.request("repos/szl-holdings/allowed")
    assert value == {"value": 1} and observed["http_status"] == 200
    assert set(observed) == {"endpoint", "http_status", "observed_at_utc"}
    command, kwargs = calls[0]
    assert command[0] == str(Path("/approved/gh"))
    assert command[command.index("--method") + 1] == "GET"
    assert kwargs["shell"] is False and "GH_DEBUG" not in kwargs["env"]
    assert "PRIVATE" not in json.dumps(reader.observations)


def test_auth_denial_retains_only_actual_status_and_fixed_code(tmp_path, monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: FakeProcess(response(401, b'{"message":"PRIVATE-ERROR"}'), b"PRIVATE-STDERR", 1))
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    with pytest.raises(sb.ReadError, match="AUTH_OR_POLICY_DENIED") as error:
        reader.request("repos/szl-holdings/allowed")
    assert error.value.status == 401 and "PRIVATE" not in str(error.value)


def test_403_exhausted_rate_quota_is_not_misclassified_auth(tmp_path, monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: FakeProcess(response(403, headers=b"X-RateLimit-Remaining: 0\n"), returncode=1))
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    with pytest.raises(sb.ReadError, match="RATE_LIMIT_STOP"):
        reader.request("repos/szl-holdings/allowed")
    assert reader.stopped and reader.calls == 1


def test_retry_after_backoff_is_bounded_to_one_retry(tmp_path, monkeypatch):
    processes = iter([FakeProcess(response(429, headers=b"Retry-After: 1\n"), returncode=1), FakeProcess(response())])
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: next(processes))
    waited = []
    monkeypatch.setattr(sb.time, "sleep", waited.append)
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    assert reader.request("repos/szl-holdings/allowed")[0] == {"value": 1}
    assert waited == [1] and reader.calls == 2


def test_403_http_date_retry_after_stops_even_with_remaining_quota(tmp_path, monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: FakeProcess(response(403, headers=b"X-RateLimit-Remaining: 4000\nRetry-After: Wed, 30 Sep 2026 11:00:00 GMT\n"), returncode=1))
    monkeypatch.setattr(sb.time, "sleep", lambda _: pytest.fail("date-form must stop without sleep"))
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    with pytest.raises(sb.ReadError, match="RATE_LIMIT_STOP"):
        reader.request("repos/szl-holdings/allowed")
    assert reader.stopped and reader.calls == 1


def test_tree_retry_counts_every_actual_attempt_at_tree_bound(tmp_path, monkeypatch):
    launched = []
    def launch(*args, **kwargs):
        launched.append(True)
        return FakeProcess(response(429, headers=b"Retry-After: 0\n"), returncode=1)
    monkeypatch.setattr(sb.subprocess, "Popen", launch)
    monkeypatch.setattr(sb.time, "sleep", lambda _: None)
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    reader.tree_calls = sb.MAX_TREE_CALLS - 1
    with pytest.raises(sb.ReadError, match="TREE_REQUEST_BOUND"):
        reader.request("repos/szl-holdings/allowed/git/trees/" + "a" * 40)
    assert len(launched) == 1 and reader.tree_calls == sb.MAX_TREE_CALLS


def test_missing_http_status_stays_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: FakeProcess(b'{"value":1}'))
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    with pytest.raises(sb.ReadError, match="TRANSPORT_HTTP_UNEXPOSED") as error:
        reader.request("repos/szl-holdings/allowed")
    assert error.value.status is None


def test_array_response_not_treated_as_object_success(tmp_path, monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: FakeProcess(response(body=b"[]")))
    with pytest.raises(sb.ReadError, match="OBJECT_RESPONSE_REQUIRED"):
        sb.GitHubRead(Path("/approved/gh"), tmp_path).request("repos/szl-holdings/allowed")


def test_request_budget_stops_without_launch(tmp_path, monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: pytest.fail("budget stop must not launch"))
    reader = sb.GitHubRead(Path("/approved/gh"), tmp_path)
    reader.calls = sb.MAX_REQUESTS
    with pytest.raises(sb.ReadError, match="REQUEST_BUDGET_OR_RATE_STOP"):
        reader.request("repos/szl-holdings/allowed")


def test_oversized_response_kills_only_owned_child(tmp_path, monkeypatch):
    process = FakeProcess(b"x" * (sb.MAX_RESPONSE + 1))
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(sb.ReadError, match="RESPONSE_BOUND_EXCEEDED"):
        sb.GitHubRead(Path("/approved/gh"), tmp_path).request("repos/szl-holdings/allowed")
    assert process.killed


def test_help_has_no_network_or_output_default(monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: pytest.fail("help must not launch"))
    with pytest.raises(SystemExit) as result:
        sb.main(["--help"])
    assert result.value.code == 0
