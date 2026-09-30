"""Typed evidence contracts. Recorded observations never imply estate readiness."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import re
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit


STATE_SCHEMA_VERSION = "szl.estate-state/v1"
REQUIRED_ESTATE_SCOPES = (
    "github:szl-holdings:full",
    "hf:SZLHOLDINGS:full",
    "domain:a-11-oy.com",
    "domain:a11oy.net",
)


class EvidenceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INACCESSIBLE = "INACCESSIBLE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class ClaimMaturity(str, Enum):
    SHIPPING = "SHIPPING"
    DEMONSTRATED = "DEMONSTRATED"
    INTERNALLY_TESTED = "INTERNALLY_TESTED"
    ROADMAP = "ROADMAP"


class ClaimBasis(str, Enum):
    FACT = "FACT"
    INFERENCE = "INFERENCE"
    PROPOSAL = "PROPOSAL"


class EvidenceFreshness(str, Enum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"


class ProofOrigin(str, Enum):
    LIVE = "LIVE"
    CACHE = "CACHE"
    LIBRARY = "LIBRARY"
    FIXTURE = "FIXTURE"
    UNKNOWN = "UNKNOWN"


class EvidenceCode(str, Enum):
    NONE = "NONE"
    AUTH_FAILED = "AUTH_FAILED"
    ACCESS_UNVERIFIED = "ACCESS_UNVERIFIED"
    RATE_LIMITED = "RATE_LIMITED"
    REMOTE_ERROR = "REMOTE_ERROR"
    PARTIAL_RESULT = "PARTIAL_RESULT"
    PAGINATION_LOOP = "PAGINATION_LOOP"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    CACHE_REPLAY = "CACHE_REPLAY"
    HISTORICAL_ONLY = "HISTORICAL_ONLY"
    OFFLINE_NOT_MEASURED = "OFFLINE_NOT_MEASURED"


class EvidenceValidationError(ValueError):
    """Validation errors contain fixed codes, never the rejected input."""


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/@-]+\Z")
_SECRET = re.compile(r"(?:gh[pousr]_|github_pat_|hf_|sk-)[A-Za-z0-9_-]{12,}|(?:bearer|password|authorization|api[_-]?key|token|secret)[=:]", re.I)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def safe_identifier(value: Any, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise EvidenceValidationError("INVALID_IDENTIFIER")
    if not _IDENTIFIER.fullmatch(value) or _SECRET.search(value):
        raise EvidenceValidationError("INVALID_IDENTIFIER")
    return value


def safe_reference(value: Any) -> str:
    value = safe_identifier(value, limit=512)
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise EvidenceValidationError("UNSAFE_REFERENCE")
    if parsed.scheme and parsed.scheme not in {"https", "http", "library", "fixture", "file", "github", "hf"}:
        raise EvidenceValidationError("UNSAFE_REFERENCE")
    return value


def utc_timestamp(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise EvidenceValidationError("INVALID_OBSERVATION_TIME")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceValidationError("INVALID_OBSERVATION_TIME") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceValidationError("INVALID_OBSERVATION_TIME")
    parsed = parsed.astimezone(timezone.utc)
    precision = "microseconds" if parsed.microsecond else "seconds"
    return parsed.isoformat(timespec=precision).replace("+00:00", "Z")


def _enum(enum_type: type[Enum], value: Any) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        raise EvidenceValidationError("INVALID_ENUM") from None


def _fields(value: Any, required: set[str], optional: set[str] | None = None) -> Mapping[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value):
        raise EvidenceValidationError("INVALID_SCHEMA")
    if set(value) - required - (optional or set()):
        raise EvidenceValidationError("INVALID_SCHEMA")
    return value


@dataclass(frozen=True, slots=True)
class EvidenceDimensions:
    cryptographic_integrity: EvidenceStatus = EvidenceStatus.UNKNOWN
    scientific_validity: EvidenceStatus = EvidenceStatus.UNKNOWN
    authorization: EvidenceStatus = EvidenceStatus.INACCESSIBLE
    deployment: EvidenceStatus = EvidenceStatus.UNKNOWN
    proof_scope: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("cryptographic_integrity", "scientific_validity", "authorization", "deployment"):
            object.__setattr__(self, name, _enum(EvidenceStatus, getattr(self, name)))
        if not isinstance(self.proof_scope, (tuple, list)) or len(self.proof_scope) > 100:
            raise EvidenceValidationError("INVALID_PROOF_SCOPE")
        scopes = tuple(sorted(safe_identifier(scope) for scope in self.proof_scope))
        if len(set(scopes)) != len(scopes):
            raise EvidenceValidationError("INVALID_PROOF_SCOPE")
        object.__setattr__(self, "proof_scope", scopes)

    @property
    def all_pass(self) -> bool:
        return all(getattr(self, name) is EvidenceStatus.PASS for name in (
            "cryptographic_integrity", "scientific_validity", "authorization", "deployment",
        ))

    def to_dict(self) -> dict[str, Any]:
        return {
            "cryptographic_integrity": self.cryptographic_integrity.value,
            "scientific_validity": self.scientific_validity.value,
            "authorization": self.authorization.value,
            "deployment": self.deployment.value,
            "proof_scope": list(self.proof_scope),
        }

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceDimensions:
        return cls(**_fields(value, {"cryptographic_integrity", "scientific_validity", "authorization", "deployment", "proof_scope"}))


@dataclass(frozen=True, slots=True)
class Provenance:
    source: str
    reference: str
    observed_at_utc: str
    scope: str
    digest: str
    freshness: EvidenceFreshness = EvidenceFreshness.UNKNOWN
    origin: ProofOrigin = ProofOrigin.UNKNOWN

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", safe_identifier(self.source, limit=64))
        object.__setattr__(self, "reference", safe_reference(self.reference))
        object.__setattr__(self, "scope", safe_identifier(self.scope))
        object.__setattr__(self, "observed_at_utc", utc_timestamp(self.observed_at_utc))
        if not isinstance(self.digest, str) or not _DIGEST.fullmatch(self.digest):
            raise EvidenceValidationError("INVALID_DIGEST")
        object.__setattr__(self, "freshness", _enum(EvidenceFreshness, self.freshness))
        object.__setattr__(self, "origin", _enum(ProofOrigin, self.origin))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "reference": self.reference,
            "observed_at_utc": self.observed_at_utc, "scope": self.scope,
            "digest": self.digest, "freshness": self.freshness.value,
            "origin": self.origin.value,
        }

    @classmethod
    def from_dict(cls, value: Any) -> Provenance:
        fields = _fields(value, {"source", "reference", "observed_at_utc", "scope", "digest", "freshness", "origin"})
        return cls(**fields)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    scope: str
    status: EvidenceStatus
    provenance: Provenance
    claim_maturity: ClaimMaturity | None = None
    claim_basis: ClaimBasis | None = None
    code: EvidenceCode = EvidenceCode.NONE
    complete: bool = False
    dimensions: EvidenceDimensions = EvidenceDimensions()
    checked_at_utc: str | None = None
    counts: Mapping[str, int | None] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_id", safe_identifier(self.evidence_id, limit=100))
        object.__setattr__(self, "scope", safe_identifier(self.scope))
        object.__setattr__(self, "status", _enum(EvidenceStatus, self.status))
        object.__setattr__(self, "code", _enum(EvidenceCode, self.code))
        if not isinstance(self.provenance, Provenance) or self.scope != self.provenance.scope:
            raise EvidenceValidationError("PROVENANCE_SCOPE_MISMATCH")
        if type(self.complete) is not bool:
            raise EvidenceValidationError("INVALID_COMPLETENESS")
        if not isinstance(self.dimensions, EvidenceDimensions):
            raise EvidenceValidationError("INVALID_DIMENSIONS")
        if self.checked_at_utc is not None:
            object.__setattr__(self, "checked_at_utc", utc_timestamp(self.checked_at_utc))
        if self.counts is not None and (not isinstance(self.counts, Mapping) or len(self.counts) > 32):
            raise EvidenceValidationError("INVALID_COUNTS")
        counts: dict[str, int | None] = {}
        for name, value in (self.counts or {}).items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
                raise EvidenceValidationError("INVALID_COUNTS")
            if _SECRET.search(name):
                raise EvidenceValidationError("INVALID_COUNTS")
            if value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1):
                raise EvidenceValidationError("INVALID_COUNTS")
            counts[name] = value
        object.__setattr__(self, "counts", MappingProxyType(dict(sorted(counts.items()))))
        for name, enum_type in (("claim_maturity", ClaimMaturity), ("claim_basis", ClaimBasis)):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _enum(enum_type, value))

    @property
    def is_live_pass(self) -> bool:
        return (
            self.status is EvidenceStatus.PASS
            and self.code is EvidenceCode.NONE
            and self.provenance.freshness is EvidenceFreshness.CURRENT
            and self.provenance.origin is ProofOrigin.LIVE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id, "scope": self.scope,
            "status": self.status.value, "provenance": self.provenance.to_dict(),
            "claim_maturity": self.claim_maturity.value if self.claim_maturity else None,
            "claim_basis": self.claim_basis.value if self.claim_basis else None,
            "code": self.code.value, "complete": self.complete,
            "dimensions": self.dimensions.to_dict(),
            "checked_at_utc": self.checked_at_utc,
            "counts": dict(self.counts or {}),
        }

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceRecord:
        fields = dict(_fields(value, {"evidence_id", "scope", "status", "provenance", "claim_maturity", "claim_basis", "code", "complete", "dimensions", "checked_at_utc", "counts"}))
        fields["provenance"] = Provenance.from_dict(fields["provenance"])
        fields["dimensions"] = EvidenceDimensions.from_dict(fields["dimensions"])
        return cls(**fields)


@dataclass(frozen=True, slots=True)
class EstateState:
    evidence: tuple[EvidenceRecord, ...]
    generated_at_utc: str
    required_scopes: tuple[str, ...] = REQUIRED_ESTATE_SCOPES
    schema_version: str = STATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != STATE_SCHEMA_VERSION:
            raise EvidenceValidationError("UNSUPPORTED_STATE_SCHEMA")
        object.__setattr__(self, "generated_at_utc", utc_timestamp(self.generated_at_utc))
        if not isinstance(self.evidence, (tuple, list)) or len(self.evidence) > 10000:
            raise EvidenceValidationError("INVALID_EVIDENCE")
        if any(not isinstance(item, EvidenceRecord) for item in self.evidence):
            raise EvidenceValidationError("INVALID_EVIDENCE")
        evidence = tuple(sorted(self.evidence, key=lambda item: (item.scope, item.evidence_id)))
        if len({item.evidence_id for item in evidence}) != len(evidence):
            raise EvidenceValidationError("DUPLICATE_EVIDENCE_ID")
        object.__setattr__(self, "evidence", evidence)
        if not isinstance(self.required_scopes, (tuple, list)) or not self.required_scopes or len(self.required_scopes) > 100:
            raise EvidenceValidationError("INVALID_REQUIRED_SCOPES")
        scopes = tuple(sorted(safe_identifier(scope) for scope in self.required_scopes))
        if len(set(scopes)) != len(scopes):
            raise EvidenceValidationError("DUPLICATE_REQUIRED_SCOPE")
        object.__setattr__(self, "required_scopes", scopes)

    @property
    def estate_ready(self) -> bool:
        required = set(self.required_scopes)
        if not set(REQUIRED_ESTATE_SCOPES).issubset(required):
            return False
        if not self.evidence or any(not item.is_live_pass for item in self.evidence):
            return False
        generated = datetime.fromisoformat(self.generated_at_utc.replace("Z", "+00:00"))
        for item in self.evidence:
            if not item.dimensions.all_pass or item.scope not in item.dimensions.proof_scope or item.checked_at_utc is None:
                return False
            checked = datetime.fromisoformat(item.checked_at_utc.replace("Z", "+00:00"))
            observed = datetime.fromisoformat(item.provenance.observed_at_utc.replace("Z", "+00:00"))
            if not 0 <= (generated - checked).total_seconds() <= 3600:
                return False
            if not 0 <= (generated - observed).total_seconds() <= 3600 or checked < observed:
                return False
        complete_live = {item.scope for item in self.evidence if item.complete and item.is_live_pass}
        return required.issubset(complete_live)

    @property
    def ready(self) -> bool:
        return self.estate_ready

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_utc": self.generated_at_utc,
            "required_scopes": list(self.required_scopes),
            "estate_ready": self.estate_ready,
            "evidence": [item.to_dict() for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, value: Any) -> EstateState:
        fields = _fields(value, {"schema_version", "generated_at_utc", "required_scopes", "estate_ready", "evidence"})
        if not isinstance(fields["evidence"], list) or type(fields["estate_ready"]) is not bool:
            raise EvidenceValidationError("INVALID_SCHEMA")
        state = cls(
            evidence=tuple(EvidenceRecord.from_dict(item) for item in fields["evidence"]),
            generated_at_utc=fields["generated_at_utc"],
            required_scopes=fields["required_scopes"],
            schema_version=fields["schema_version"],
        )
        if state.estate_ready != fields["estate_ready"]:
            raise EvidenceValidationError("READINESS_MISMATCH")
        return state
