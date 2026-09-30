"""Four narrow, read-only access observations; receipts are not estate authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import re
import subprocess
import threading
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .model import EvidenceCode, EvidenceStatus, EvidenceValidationError, safe_identifier, utc_timestamp
from .storage import StorageError, atomic_write, integrity_bytes, read_integrity_payload, sha256_digest


RECEIPT_SCHEMA = "szl.access-receipt/v1"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 32 * 1024
TIMEOUT_SECONDS = 15
HF_ENDPOINT = "https://huggingface.co/api/whoami-v2"


class AccessSource(str, Enum):
    GH_API = "gh_api"
    HF_HTTPS = "hf_https"


ACCESS_SPECS = {
    "github:user": (AccessSource.GH_API, "/user"),
    "github:org:szl-holdings": (AccessSource.GH_API, "/orgs/szl-holdings"),
    "github:membership:szl-holdings": (AccessSource.GH_API, "/user/memberships/orgs/szl-holdings"),
    "hf:whoami:SZLHOLDINGS": (AccessSource.HF_HTTPS, HF_ENDPOINT),
}
_HF_ROLES = {"read", "write", "contributor", "admin"}


class AccessError(ValueError):
    """Only fixed validation codes are exposed, never transport or token text."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _identifier(value: Any) -> str | None:
    try:
        clean = safe_identifier(value, limit=64)
        return clean if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", clean) else None
    except EvidenceValidationError:
        return None


@dataclass(frozen=True, slots=True)
class AccessObservation:
    scope: str
    status: EvidenceStatus
    source: AccessSource
    endpoint: str
    observed_at_utc: str
    http_status: int | None
    username: str | None
    identity_id: int | None
    org: str | None
    state: str | None
    member_role: str | None
    code: EvidenceCode
    digest: str

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "status", EvidenceStatus(self.status))
            object.__setattr__(self, "source", AccessSource(self.source))
            object.__setattr__(self, "code", EvidenceCode(self.code))
            object.__setattr__(self, "observed_at_utc", utc_timestamp(self.observed_at_utc))
        except (ValueError, TypeError):
            raise AccessError("INVALID_ACCESS_OBSERVATION") from None
        if not isinstance(self.scope, str) or self.scope not in ACCESS_SPECS or (self.source, self.endpoint) != ACCESS_SPECS[self.scope]:
            raise AccessError("INVALID_ACCESS_BINDING")
        if self.http_status is not None and (type(self.http_status) is not int or not 100 <= self.http_status <= 599):
            raise AccessError("INVALID_ACCESS_OBSERVATION")
        if self.identity_id is not None and (type(self.identity_id) is not int or not 1 <= self.identity_id <= 2**63 - 1):
            raise AccessError("INVALID_ACCESS_OBSERVATION")
        for value in (self.username, self.org):
            if value is not None and _identifier(value) != value:
                raise AccessError("INVALID_ACCESS_OBSERVATION")
        if self.state is not None and self.state not in ("active", "pending"):
            raise AccessError("INVALID_ACCESS_OBSERVATION")
        if self.member_role is not None and (not isinstance(self.member_role, str) or self.member_role not in _HF_ROLES | {"member"}):
            raise AccessError("INVALID_ACCESS_OBSERVATION")
        if self.status is EvidenceStatus.PASS and not self._facts_pass():
            raise AccessError("FALSE_ACCESS_PASS")
        if not isinstance(self.digest, str) or self.digest != sha256_digest(self.projection()):
            raise AccessError("ACCESS_DIGEST_MISMATCH")

    def _facts_pass(self) -> bool:
        if self.http_status != 200 or self.code is not EvidenceCode.NONE:
            return False
        if self.scope == "github:user":
            return bool(self.username and self.identity_id)
        if self.scope == "github:org:szl-holdings":
            return self.org == "szl-holdings" and self.identity_id is not None
        if self.scope == "github:membership:szl-holdings":
            return bool(self.username) and self.org == "szl-holdings" and self.state == "active" and self.member_role in {"admin", "member"}
        return bool(self.username) and self.org == "SZLHOLDINGS" and self.member_role in _HF_ROLES

    @property
    def phase0_pass(self) -> bool:
        return self.status is EvidenceStatus.PASS and self._facts_pass()

    @property
    def estate_ready(self) -> bool:
        return False

    def projection(self) -> dict[str, Any]:
        return {"scope": self.scope, "status": self.status.value, "source": self.source.value,
                "endpoint": self.endpoint, "http_status": self.http_status, "username": self.username,
                "identity_id": self.identity_id, "org": self.org, "state": self.state,
                "member_role": self.member_role, "code": self.code.value}

    def to_dict(self) -> dict[str, Any]:
        return {**self.projection(), "observed_at_utc": self.observed_at_utc, "digest": self.digest}

    @classmethod
    def from_dict(cls, value: Any) -> AccessObservation:
        required = {"scope", "status", "source", "endpoint", "observed_at_utc", "http_status", "username", "identity_id", "org", "state", "member_role", "code", "digest"}
        if not isinstance(value, dict) or set(value) != required:
            raise AccessError("INVALID_ACCESS_OBSERVATION")
        return cls(**value)


def _json_object(raw: bytes) -> dict[str, Any] | None:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeError, RecursionError):
        return None


def _response_code(status: int | None) -> EvidenceCode:
    if status in (401, 403):
        return EvidenceCode.AUTH_FAILED
    if status == 429:
        return EvidenceCode.RATE_LIMITED
    return EvidenceCode.NONE if status == 200 else EvidenceCode.REMOTE_ERROR


def _gh_response(endpoint: str) -> tuple[int | None, dict[str, Any] | None, EvidenceCode]:
    if endpoint not in {spec[1] for spec in ACCESS_SPECS.values() if spec[0] is AccessSource.GH_API}:
        raise AccessError("INVALID_ACCESS_BINDING")
    chunks: list[bytes] = []
    try:
        process = subprocess.Popen(["gh", "api", "--hostname", "github.com", "--include", "--method", "GET", endpoint], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        def read_bounded():
            try:
                raw = process.stdout.read(MAX_RESPONSE_BYTES + 1)
                chunks.append(raw)
                if len(raw) > MAX_RESPONSE_BYTES:
                    process.kill()
            except OSError:
                pass
        reader = threading.Thread(target=read_bounded, daemon=True)
        reader.start()
        try:
            process.wait(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            return None, None, EvidenceCode.REMOTE_ERROR
        finally:
            reader.join(timeout=2)
            process.stdout.close()
    except (OSError, subprocess.SubprocessError):
        return None, None, EvidenceCode.ACCESS_UNVERIFIED
    raw = chunks[0] if chunks else b""
    if len(raw) > MAX_RESPONSE_BYTES:
        return None, None, EvidenceCode.INVALID_RESPONSE
    match = re.match(rb"HTTP/[^\s]+\s+(\d{3})[^\r\n]*\r?\n", raw)
    if not match:
        return None, None, EvidenceCode.AUTH_FAILED if process.returncode == 4 else EvidenceCode.INVALID_RESPONSE
    status = int(match.group(1))
    code = _response_code(status)
    if code is not EvidenceCode.NONE:
        return status, None, code
    separator = re.search(rb"\r?\n\r?\n", raw)
    body = _json_object(raw[separator.end():]) if separator else None
    if process.returncode != 0 or body is None:
        return status, None, EvidenceCode.INVALID_RESPONSE
    return status, body, EvidenceCode.NONE


def _read_hf_token() -> str | None:
    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    if not token:
        token_path = os.environ.get("HF_TOKEN_PATH")
        if token_path:
            path = Path(token_path)
        elif os.environ.get("HF_HOME"):
            path = Path(os.environ["HF_HOME"]) / "token"
        else:
            path = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "huggingface" / "token"
        try:
            with path.open("rb") as stream:
                raw = stream.read(4097)
                if len(raw) > 4096:
                    return None
                token = raw.decode("ascii")
        except (OSError, UnicodeError):
            return None
    token = token.strip()
    return token if len(token) <= 4096 and re.fullmatch(r"[A-Za-z0-9_-]+", token) else None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _hf_response() -> tuple[int | None, dict[str, Any] | None, EvidenceCode]:
    token = _read_hf_token()
    if not token:
        return None, None, EvidenceCode.ACCESS_UNVERIFIED
    request = Request(HF_ENDPOINT, headers={"Authorization": "Bearer " + token, "Accept": "application/json"}, method="GET")
    try:
        with build_opener(_NoRedirect()).open(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            if status != 200:
                return status, None, _response_code(status)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        status = error.code
        error.close()
        return status, None, _response_code(status)
    except (URLError, OSError, ValueError):
        return None, None, EvidenceCode.REMOTE_ERROR
    if len(raw) > MAX_RESPONSE_BYTES:
        return status, None, EvidenceCode.INVALID_RESPONSE
    body = _json_object(raw)
    return status, body, EvidenceCode.NONE if body is not None else EvidenceCode.INVALID_RESPONSE


def _observation(scope: str, at: str, response: tuple[int | None, dict[str, Any] | None, EvidenceCode]) -> AccessObservation:
    http_status, body, code = response
    body = body if isinstance(body, dict) and code is EvidenceCode.NONE else {}
    username = org = state = role = None
    identity_id = None
    if scope == "github:user":
        username, identity_id = _identifier(body.get("login")), body.get("id")
    elif scope == "github:org:szl-holdings":
        org, identity_id = _identifier(body.get("login")), body.get("id")
    elif scope == "github:membership:szl-holdings":
        user, organization = body.get("user"), body.get("organization")
        username = _identifier(user.get("login")) if isinstance(user, dict) else None
        org = _identifier(organization.get("login")) if isinstance(organization, dict) else None
        state = body.get("state") if body.get("state") in ("active", "pending") else None
        role = body.get("role") if body.get("role") in ("admin", "member") else None
    else:
        username = _identifier(body.get("name"))
        orgs = body.get("orgs")
        memberships = [item for item in orgs if isinstance(item, dict) and item.get("name") == "SZLHOLDINGS"] if isinstance(orgs, list) else []
        if len(memberships) == 1:
            member = memberships[0]
            candidate = member.get("roleInOrg", member.get("role"))
            if isinstance(candidate, str) and candidate in _HF_ROLES and ("role" not in member or "roleInOrg" not in member or member["role"] == member["roleInOrg"]):
                org, role = "SZLHOLDINGS", candidate
    if type(identity_id) is not int or not 1 <= identity_id <= 2**63 - 1:
        identity_id = None
    status = EvidenceStatus.INACCESSIBLE if code is EvidenceCode.AUTH_FAILED else EvidenceStatus.NOT_RUN if code is EvidenceCode.ACCESS_UNVERIFIED else EvidenceStatus.UNKNOWN
    source, endpoint = ACCESS_SPECS[scope]
    fields = dict(scope=scope, status=status, source=source, endpoint=endpoint, observed_at_utc=at, http_status=http_status, username=username, identity_id=identity_id, org=org, state=state, member_role=role, code=code)
    projected = {key: value.value if isinstance(value, Enum) else value for key, value in fields.items() if key != "observed_at_utc"}
    observation = AccessObservation(**fields, digest=sha256_digest(projected))
    if observation._facts_pass():
        fields["status"] = EvidenceStatus.PASS
    elif code is EvidenceCode.NONE:
        fields["code"] = EvidenceCode.INVALID_RESPONSE
    projected = {key: value.value if isinstance(value, Enum) else value for key, value in fields.items() if key != "observed_at_utc"}
    return AccessObservation(**fields, digest=sha256_digest(projected))


def collect_access(*, observed_at_utc: str | None = None) -> tuple[AccessObservation, ...]:
    at = utc_timestamp(observed_at_utc or _now())
    observations = tuple(_observation(scope, at, _gh_response(endpoint) if source is AccessSource.GH_API else _hf_response()) for scope, (source, endpoint) in ACCESS_SPECS.items())
    user, _, membership, _ = observations
    if membership.phase0_pass and (not user.phase0_pass or user.username != membership.username):
        fields = membership.to_dict()
        fields["status"], fields["code"] = "UNKNOWN", "INVALID_RESPONSE"
        fields["digest"] = sha256_digest({key: value for key, value in fields.items() if key not in {"digest", "observed_at_utc"}})
        observations = tuple(AccessObservation.from_dict(fields) if item.scope == membership.scope else item for item in observations)
    return observations


def _complete(observations: Iterable[AccessObservation], now_utc: str) -> tuple[AccessObservation, ...]:
    items = tuple(observations)
    if len(items) != 4 or any(not isinstance(item, AccessObservation) for item in items) or {item.scope for item in items} != set(ACCESS_SPECS):
        raise AccessError("PARTIAL_ACCESS_RECEIPT")
    now = datetime.fromisoformat(utc_timestamp(now_utc).replace("Z", "+00:00"))
    for item in items:
        observed = datetime.fromisoformat(item.observed_at_utc.replace("Z", "+00:00"))
        if not 0 <= (now - observed).total_seconds() <= 3600:
            raise AccessError("STALE_ACCESS_RECEIPT")
        if not item.phase0_pass:
            raise AccessError("UNVERIFIED_ACCESS_RECEIPT")
    by_scope = {item.scope: item for item in items}
    if by_scope["github:user"].username != by_scope["github:membership:szl-holdings"].username:
        raise AccessError("ACCESS_IDENTITY_MISMATCH")
    return tuple(by_scope[scope] for scope in ACCESS_SPECS)


def save_access_receipt(path: Path | str, observations: Iterable[AccessObservation], *, now_utc: str | None = None) -> Path:
    items = _complete(observations, now_utc or _now())
    raw = integrity_bytes({"schema_version": RECEIPT_SCHEMA, "observations": [item.to_dict() for item in items]})
    if len(raw) > MAX_RECEIPT_BYTES:
        raise AccessError("ACCESS_RECEIPT_TOO_LARGE")
    return atomic_write(path, raw)


def load_access_receipt(path: Path | str, *, now_utc: str | None = None) -> tuple[AccessObservation, ...]:
    try:
        payload = read_integrity_payload(path, max_bytes=MAX_RECEIPT_BYTES)
    except StorageError:
        raise AccessError("INVALID_ACCESS_RECEIPT") from None
    if set(payload) != {"schema_version", "observations"} or payload["schema_version"] != RECEIPT_SCHEMA or not isinstance(payload["observations"], list) or len(payload["observations"]) != 4:
        raise AccessError("PARTIAL_ACCESS_RECEIPT")
    return _complete((AccessObservation.from_dict(item) for item in payload["observations"]), now_utc or _now())


def validate_access_receipt(path: Path | str, fresh_observations: Iterable[AccessObservation], *, now_utc: str | None = None) -> tuple[AccessObservation, ...]:
    now = now_utc or _now()
    recorded = load_access_receipt(path, now_utc=now)
    fresh = _complete(fresh_observations, now)
    if any(old.source is not live.source or old.endpoint != live.endpoint or old.digest != live.digest or old.projection() != live.projection() for old, live in zip(recorded, fresh)):
        raise AccessError("ACCESS_RECEIPT_MISMATCH")
    return fresh  # fresh observations, never receipt authority
