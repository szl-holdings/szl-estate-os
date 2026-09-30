"""Injected access transports only: no real credentials, subprocess or network."""

from io import BytesIO
import json
from pathlib import Path
import subprocess
from urllib.error import HTTPError, URLError

import pytest

from szl_estate import access
from szl_estate.access import AccessError, AccessObservation, AccessSource
from szl_estate.model import EvidenceCode, EvidenceStatus
from szl_estate.storage import integrity_bytes, sha256_digest


NOW = "2026-09-30T12:00:00Z"


@pytest.fixture
def transports(monkeypatch):
    github = {
        "/user": {"login": "owner", "id": 123, "email": "private@example.com", "token": "do-not-log"},
        "/orgs/szl-holdings": {"login": "szl-holdings", "id": 456},
        "/user/memberships/orgs/szl-holdings": {"user": {"login": "owner"}, "organization": {"login": "szl-holdings"}, "state": "active", "role": "admin"},
    }
    huggingface = {"name": "owner", "email": "private@example.com", "orgs": [{"name": "SZLHOLDINGS", "roleInOrg": "admin"}]}
    monkeypatch.setattr(access, "_gh_response", lambda endpoint: (200, github[endpoint], EvidenceCode.NONE))
    monkeypatch.setattr(access, "_hf_response", lambda: (200, huggingface, EvidenceCode.NONE))
    return github, huggingface


def test_four_narrow_scopes_project_only_safe_access_fields(transports):
    observations = access.collect_access(observed_at_utc=NOW)
    assert tuple(item.scope for item in observations) == tuple(access.ACCESS_SPECS)
    assert all(item.phase0_pass and item.http_status == 200 for item in observations)
    assert not any(item.estate_ready for item in observations)
    serialized = json.dumps([item.to_dict() for item in observations])
    assert "private@example.com" not in serialized and "do-not-log" not in serialized
    assert all(AccessObservation.from_dict(item.to_dict()) == item for item in observations)


@pytest.mark.parametrize("http,code,status", [(401, EvidenceCode.AUTH_FAILED, EvidenceStatus.INACCESSIBLE), (403, EvidenceCode.AUTH_FAILED, EvidenceStatus.INACCESSIBLE), (None, EvidenceCode.ACCESS_UNVERIFIED, EvidenceStatus.NOT_RUN)])
def test_auth_failures_or_unmeasured_access_cannot_pass(transports, monkeypatch, http, code, status):
    monkeypatch.setattr(access, "_gh_response", lambda endpoint: (http, None, code))
    monkeypatch.setattr(access, "_hf_response", lambda: (http, None, code))
    observations = access.collect_access(observed_at_utc=NOW)
    assert all(item.status is status and not item.phase0_pass for item in observations)


@pytest.mark.parametrize("http,body,code", [(None, {"login": "owner", "id": 1}, EvidenceCode.NONE), (302, None, EvidenceCode.REMOTE_ERROR), (429, None, EvidenceCode.RATE_LIMITED), (503, None, EvidenceCode.REMOTE_ERROR), (200, {}, EvidenceCode.NONE)])
def test_unknown_http_redirect_rate_limit_errors_or_missing_facts_not_pass(transports, monkeypatch, http, body, code):
    monkeypatch.setattr(access, "_gh_response", lambda endpoint: (http, body, code))
    observations = access.collect_access(observed_at_utc=NOW)
    assert all(not item.phase0_pass for item in observations[:3])


@pytest.mark.parametrize("mutation", ["pending", "wrong_org", "wrong_identity", "missing_role"])
def test_github_membership_requires_exact_active_bound_member(transports, mutation):
    github, _ = transports
    member = github["/user/memberships/orgs/szl-holdings"]
    if mutation == "pending":
        member["state"] = "pending"
    elif mutation == "wrong_org":
        member["organization"]["login"] = "another-org"
    elif mutation == "wrong_identity":
        member["user"]["login"] = "someone-else"
    else:
        member.pop("role")
    observed = access.collect_access(observed_at_utc=NOW)[2]
    assert observed.status is EvidenceStatus.UNKNOWN and not observed.phase0_pass


@pytest.mark.parametrize("memberships", [[], [{"name": "different", "role": "admin"}], [{"name": "SZLHOLDINGS"}], [{"name": "SZLHOLDINGS", "role": "admin", "roleInOrg": "read"}], [{"name": "SZLHOLDINGS", "role": "admin"}, {"name": "SZLHOLDINGS", "role": "admin"}]])
def test_hf_requires_exact_unambiguous_membership_role(transports, memberships):
    _, hf = transports
    hf["orgs"] = memberships
    observed = access.collect_access(observed_at_utc=NOW)[3]
    assert not observed.phase0_pass


def test_observation_exact_schema_source_binding_and_digest(transports):
    original = access.collect_access(observed_at_utc=NOW)[0].to_dict()
    for mutation in ({"unknown": "private-value"}, {"source": "connector"}, {"endpoint": "/repos"}, {"digest": "f" * 64}):
        with pytest.raises(AccessError):
            AccessObservation.from_dict({**original, **mutation})
    malformed = {**original, "http_status": None}
    malformed["digest"] = sha256_digest({key: value for key, value in malformed.items() if key not in {"digest", "observed_at_utc"}})
    with pytest.raises(AccessError, match="^FALSE_ACCESS_PASS$"):
        AccessObservation.from_dict(malformed)


def test_receipt_roundtrip_requires_fresh_facts_and_does_not_confer_readiness(transports, tmp_path):
    original = access.collect_access(observed_at_utc=NOW)
    path = access.save_access_receipt(tmp_path / "access.json", original, now_utc=NOW)
    assert path.stat().st_size < access.MAX_RECEIPT_BYTES
    assert access.load_access_receipt(path, now_utc=NOW) == original
    fresh = access.collect_access(observed_at_utc="2026-09-30T12:01:00Z")
    assert access.validate_access_receipt(path, fresh, now_utc="2026-09-30T12:01:00Z") == fresh
    assert not any(item.estate_ready for item in original)


@pytest.mark.parametrize("validation_time", ["2026-09-30T11:59:59Z", "2026-09-30T13:00:01Z"])
def test_future_or_stale_receipt_rejected(transports, tmp_path, validation_time):
    path = access.save_access_receipt(tmp_path / "access.json", access.collect_access(observed_at_utc=NOW), now_utc=NOW)
    with pytest.raises(AccessError, match="^STALE_ACCESS_RECEIPT$"):
        access.load_access_receipt(path, now_utc=validation_time)


def test_partial_receipt_or_inaccessible_fresh_facts_rejected(transports, monkeypatch, tmp_path):
    observations = access.collect_access(observed_at_utc=NOW)
    with pytest.raises(AccessError, match="^PARTIAL_ACCESS_RECEIPT$"):
        access.save_access_receipt(tmp_path / "partial.json", observations[:3], now_utc=NOW)
    path = access.save_access_receipt(tmp_path / "access.json", observations, now_utc=NOW)
    monkeypatch.setattr(access, "_hf_response", lambda: (401, None, EvidenceCode.AUTH_FAILED))
    with pytest.raises(AccessError, match="^UNVERIFIED_ACCESS_RECEIPT$"):
        access.validate_access_receipt(path, access.collect_access(observed_at_utc=NOW), now_utc=NOW)


def test_integrity_valid_forged_identity_rejected_against_fresh_facts(transports, tmp_path):
    path = access.save_access_receipt(tmp_path / "access.json", access.collect_access(observed_at_utc=NOW), now_utc=NOW)
    payload = json.loads(path.read_text())["payload"]
    for item in payload["observations"]:
        if item["scope"] in {"github:user", "github:membership:szl-holdings"}:
            item["username"] = "forged-owner"
            item["digest"] = sha256_digest({key: value for key, value in item.items() if key not in {"digest", "observed_at_utc"}})
    path.write_bytes(integrity_bytes(payload))
    with pytest.raises(AccessError, match="^ACCESS_RECEIPT_MISMATCH$"):
        access.validate_access_receipt(path, access.collect_access(observed_at_utc=NOW), now_utc=NOW)


def test_corrupt_oversize_and_partial_receipts_are_fixed_errors(transports, tmp_path):
    path = tmp_path / "access.json"
    path.write_bytes(b"private broken json")
    with pytest.raises(AccessError, match="^INVALID_ACCESS_RECEIPT$"):
        access.load_access_receipt(path, now_utc=NOW)
    path.write_bytes(b"x" * (access.MAX_RECEIPT_BYTES + 1))
    with pytest.raises(AccessError, match="^INVALID_ACCESS_RECEIPT$"):
        access.load_access_receipt(path, now_utc=NOW)
    observations = access.collect_access(observed_at_utc=NOW)
    path.write_bytes(integrity_bytes({"schema_version": access.RECEIPT_SCHEMA, "observations": [item.to_dict() for item in observations[:3]]}))
    with pytest.raises(AccessError, match="^PARTIAL_ACCESS_RECEIPT$"):
        access.load_access_receipt(path, now_utc=NOW)


class FakeProcess:
    def __init__(self, raw, returncode=0):
        self.stdout = BytesIO(raw)
        self.returncode = returncode
        self.killed = False

    def wait(self, timeout):
        return self.returncode

    def kill(self):
        self.killed = True


def test_gh_include_projects_http_and_bounds_subprocess_output(monkeypatch):
    process = FakeProcess(b'HTTP/2.0 200 OK\r\nX-Private: do-not-log\r\n\r\n{"login":"owner","id":1}')
    calls = []
    def popen(command, **kwargs):
        calls.append((command, kwargs))
        return process
    monkeypatch.setattr(access.subprocess, "Popen", popen)
    http, body, code = access._gh_response("/user")
    assert (http, body, code) == (200, {"login": "owner", "id": 1}, EvidenceCode.NONE)
    assert calls[0][0] == ["gh", "api", "--hostname", "github.com", "--include", "--method", "GET", "/user"]
    assert calls[0][1]["stderr"] == subprocess.DEVNULL
    process = FakeProcess(b"x" * (access.MAX_RESPONSE_BYTES + 1))
    assert access._gh_response("/user")[2] is EvidenceCode.INVALID_RESPONSE
    assert process.killed


@pytest.mark.parametrize("raw,returncode,expected", [(b'HTTP/2.0 401 Unauthorized\n\n{"message":"private"}', 1, EvidenceCode.AUTH_FAILED), (b'HTTP/2.0 200 OK\n\n{"login":"a","login":"b"}', 0, EvidenceCode.INVALID_RESPONSE), (b"auth error private", 4, EvidenceCode.AUTH_FAILED)])
def test_gh_error_or_duplicate_json_is_not_success(monkeypatch, raw, returncode, expected):
    monkeypatch.setattr(access.subprocess, "Popen", lambda *args, **kwargs: FakeProcess(raw, returncode))
    assert access._gh_response("/user")[2] is expected


def test_hf_existing_token_precedence_and_file_read_are_only_fixture_data(monkeypatch, tmp_path):
    for name in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HF_TOKEN_PATH", "HF_HOME", "XDG_CACHE_HOME"):
        monkeypatch.delenv(name, raising=False)
    fixture = tmp_path / "token"
    fixture.write_text("hf_fixture_token")
    monkeypatch.setenv("HF_TOKEN_PATH", str(fixture))
    assert access._read_hf_token() == "hf_fixture_token"
    monkeypatch.setenv("HF_TOKEN", "hf_environment_token")
    assert access._read_hf_token() == "hf_environment_token"
    monkeypatch.delenv("HF_TOKEN")
    fixture.write_bytes(b"x" * 4097)
    assert access._read_hf_token() is None


def test_hf_no_redirect_handler_never_forwards_authorization(monkeypatch):
    monkeypatch.setattr(access, "_read_hf_token", lambda: "hf_fixture_token")
    calls = []
    class Opener:
        def open(self, request, timeout):
            calls.append((request, timeout))
            raise HTTPError(request.full_url, 302, "private redirect", {}, None)
    def build(handler):
        assert isinstance(handler, access._NoRedirect)
        assert handler.redirect_request(None, None, 302, "private", {}, "https://untrusted.example") is None
        return Opener()
    monkeypatch.setattr(access, "build_opener", build)
    assert access._hf_response() == (302, None, EvidenceCode.REMOTE_ERROR)
    assert len(calls) == 1 and calls[0][0].full_url == access.HF_ENDPOINT
    assert calls[0][1] == 15


@pytest.mark.parametrize("code", [401, 403, 429, 503])
def test_hf_http_error_retains_only_actual_status_and_fixed_code(monkeypatch, code):
    monkeypatch.setattr(access, "_read_hf_token", lambda: "hf_fixture_token")
    class Opener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, code, "private error text", {}, None)
    monkeypatch.setattr(access, "build_opener", lambda *args: Opener())
    http, body, error = access._hf_response()
    assert http == code and body is None and error is access._response_code(code)


def test_hf_timeout_and_missing_token_are_unknown_without_raw_error(monkeypatch):
    monkeypatch.setattr(access, "_read_hf_token", lambda: None)
    assert access._hf_response() == (None, None, EvidenceCode.ACCESS_UNVERIFIED)
    monkeypatch.setattr(access, "_read_hf_token", lambda: "hf_fixture_token")
    class Opener:
        def open(self, request, timeout):
            raise URLError("private error text")
    monkeypatch.setattr(access, "build_opener", lambda *args: Opener())
    assert access._hf_response() == (None, None, EvidenceCode.REMOTE_ERROR)
