"""Pure response parsing and bounded pagination with an injected fetcher.

This module performs no network access. Error codes contain no response text,
URLs, credentials, or exception messages. Partial records remain inspectable,
but a failed collection is never marked complete.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any


_PARSE_ERRORS = frozenset({
    "API_ERRORS", "OBJECT_COLLECTION_KEY_REQUIRED", "INVALID_COLLECTION_KEY",
    "MISSING_COLLECTION", "INVALID_PAGE_SHAPE", "INVALID_COLLECTION_SHAPE",
    "INVALID_RECORD_SHAPE", "INVALID_TOTAL_COUNT", "INVALID_CURSOR",
    "GRAPHQL_ERRORS", "INVALID_CONNECTION_PATH", "MISSING_CONNECTION",
    "INVALID_CONNECTION_SHAPE", "INVALID_PAGE_INFO", "MISSING_NEXT_CURSOR",
})


class CollectionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INACCESSIBLE = "INACCESSIBLE"


class CountStatus(str, Enum):
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


@dataclass(frozen=True)
class CommentCount:
    count: int | None
    status: CountStatus


@dataclass(frozen=True)
class ParsedPage:
    items: tuple[dict[str, Any], ...] = ()
    has_next: bool = False
    next_cursor: str | None = None
    total_count: int | None = None
    errors: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class PageResponse:
    """Minimal transport facts supplied by an authorized caller, without headers."""

    payload: object
    status_code: int = 200
    next_cursor: str | None = None
    rate_limited: bool = False
    retry_after_seconds: float | None = None


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 5.0


@dataclass(frozen=True)
class PaginationResult:
    items: tuple[dict[str, Any], ...]
    status: CollectionStatus
    pages_fetched: int
    attempts: int
    retries: int
    next_cursor: str | None
    errors: tuple[str, ...] = ()
    total_count: int | None = None

    @property
    def complete(self) -> bool:
        return self.status is CollectionStatus.COMPLETE and not self.errors


def parse_comment_count(value: object = None) -> CommentCount:
    """Missing/null is unknown; bool and negative counters are invalid."""

    if value is None:
        return CommentCount(None, CountStatus.UNKNOWN)
    if type(value) is int:
        return CommentCount(value, CountStatus.KNOWN) if value >= 0 else CommentCount(None, CountStatus.INVALID)
    if isinstance(value, list):
        return CommentCount(len(value), CountStatus.KNOWN)
    if isinstance(value, Mapping):
        if "totalCount" not in value:
            return CommentCount(None, CountStatus.UNKNOWN)
        counter = value["totalCount"]
        if counter is None:
            return CommentCount(None, CountStatus.UNKNOWN)
        if type(counter) is int and counter >= 0:
            return CommentCount(counter, CountStatus.KNOWN)
    return CommentCount(None, CountStatus.INVALID)


def _records(raw: object) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    if not isinstance(raw, list):
        return (), ("INVALID_COLLECTION_SHAPE",)
    items = tuple(dict(item) for item in raw if isinstance(item, Mapping))
    errors = () if len(items) == len(raw) else ("INVALID_RECORD_SHAPE",)
    return items, errors


def _counter(raw: object) -> tuple[int | None, tuple[str, ...]]:
    if raw is None:
        return None, ()
    if type(raw) is int and raw >= 0:
        return raw, ()
    return None, ("INVALID_TOTAL_COUNT",)


def parse_rest_page(
    payload: object,
    *,
    collection_key: str | None = None,
    next_cursor: str | None = None,
) -> ParsedPage:
    """Accept an array, or an object under an explicitly named collection key.

    Object values are never guessed as collections. The caller must supply the
    next cursor from its validated transport metadata; this parser fetches none.
    """

    errors: list[str] = []
    total_count = None
    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, Mapping):
        response_errors = payload.get("errors")
        if ((response_errors is not None and (not isinstance(response_errors, list) or response_errors))
                or ("error" in payload and payload["error"] is not None)):
            errors.append("API_ERRORS")
        if collection_key is None:
            return ParsedPage(errors=("OBJECT_COLLECTION_KEY_REQUIRED",))
        if not isinstance(collection_key, str) or not collection_key:
            return ParsedPage(errors=tuple(errors + ["INVALID_COLLECTION_KEY"]))
        if collection_key not in payload:
            return ParsedPage(errors=tuple(errors + ["MISSING_COLLECTION"]))
        raw_items = payload[collection_key]
        total_count, count_errors = _counter(payload.get("total_count", payload.get("totalCount")))
        errors.extend(count_errors)
    else:
        return ParsedPage(errors=("INVALID_PAGE_SHAPE",))
    items, record_errors = _records(raw_items)
    errors.extend(record_errors)
    if next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor.strip()):
        errors.append("INVALID_CURSOR")
        next_cursor = None
    return ParsedPage(items, next_cursor is not None, next_cursor, total_count, tuple(errors))


def parse_github_graphql_page(payload: object, *, connection_path: Sequence[str]) -> ParsedPage:
    """Parse a GraphQL data connection with nodes and explicit pageInfo.

    GraphQL errors invalidate the page even when the response includes data.
    Valid partial nodes are retained as evidence, never as a successful page.
    """

    if not isinstance(payload, Mapping):
        return ParsedPage(errors=("INVALID_PAGE_SHAPE",))
    errors: list[str] = []
    graphql_errors = payload.get("errors")
    if graphql_errors is not None and (not isinstance(graphql_errors, list) or graphql_errors):
        errors.append("GRAPHQL_ERRORS")
    connection: object = payload.get("data")
    if not connection_path or isinstance(connection_path, (str, bytes)):
        return ParsedPage(errors=tuple(errors + ["INVALID_CONNECTION_PATH"]))
    for key in connection_path:
        if not isinstance(key, str) or not isinstance(connection, Mapping) or key not in connection:
            return ParsedPage(errors=tuple(errors + ["MISSING_CONNECTION"]))
        connection = connection[key]
    if not isinstance(connection, Mapping):
        return ParsedPage(errors=tuple(errors + ["INVALID_CONNECTION_SHAPE"]))
    items, record_errors = _records(connection.get("nodes"))
    errors.extend(record_errors)
    total_count, count_errors = _counter(connection.get("totalCount"))
    errors.extend(count_errors)
    page_info = connection.get("pageInfo")
    if not isinstance(page_info, Mapping) or type(page_info.get("hasNextPage")) is not bool:
        return ParsedPage(items, total_count=total_count, errors=tuple(errors + ["INVALID_PAGE_INFO"]))
    has_next = page_info["hasNextPage"]
    cursor = page_info.get("endCursor")
    if cursor is not None and (not isinstance(cursor, str) or not cursor.strip()):
        errors.append("INVALID_CURSOR")
        cursor = None
    if has_next and cursor is None:
        errors.append("MISSING_NEXT_CURSOR")
    return ParsedPage(items, has_next, cursor if has_next else None, total_count, tuple(errors))


def _retry_delay(response: PageResponse, attempt: int, policy: RetryPolicy) -> float | None:
    explicit = response.retry_after_seconds
    if type(explicit) in (int, float) and explicit >= 0:
        # A provider's minimum wait must never be shortened to our budget.
        if explicit > policy.max_delay_seconds:
            return None
        return float(explicit)
    return min(policy.base_delay_seconds * (2 ** (attempt - 1)), policy.max_delay_seconds)


def collect_pages(
    fetcher: Callable[[str | None], PageResponse],
    parser: Callable[[PageResponse], ParsedPage],
    *,
    initial_cursor: str | None = None,
    max_pages: int = 20,
    identity_key: str | None = None,
    retry_policy: RetryPolicy = RetryPolicy(),
    wait: Callable[[float], None] | None = None,
) -> PaginationResult:
    """Bounded pagination; retries require a caller-supplied backoff function.

    Fetchers and parsers are injected. No URL, token, raw exception, or response
    text is retained in errors. Without ``wait``, rate limits fail immediately.
    The returned cursor identifies the failed page for a caller-managed resume.
    Known totals must reconcile; ``identity_key`` adds explicit duplicate and
    missing-identity detection without guessing a provider's record schema.
    """

    if type(max_pages) is not int or max_pages < 1:
        raise ValueError("INVALID_MAX_PAGES")
    if type(retry_policy.max_attempts) is not int or retry_policy.max_attempts < 1:
        raise ValueError("INVALID_RETRY_POLICY")
    for delay in (retry_policy.base_delay_seconds, retry_policy.max_delay_seconds):
        if type(delay) not in (int, float) or not 0 <= delay < float("inf"):
            raise ValueError("INVALID_RETRY_POLICY")
    if initial_cursor is not None and (not isinstance(initial_cursor, str) or not initial_cursor.strip()):
        raise ValueError("INVALID_INITIAL_CURSOR")
    if identity_key is not None and (not isinstance(identity_key, str) or not identity_key or len(identity_key) > 128):
        raise ValueError("INVALID_IDENTITY_KEY")
    items: list[dict[str, Any]] = []
    visited: set[str | None] = set()
    identities: set[str | int] = set()
    expected_total: int | None = None
    pages_fetched = completed_pages = attempts = retries = 0
    cursor = initial_cursor

    def failed(code: str | tuple[str, ...]) -> PaginationResult:
        status = CollectionStatus.PARTIAL if completed_pages or items else CollectionStatus.INACCESSIBLE
        codes = (code,) if isinstance(code, str) else code
        return PaginationResult(tuple(items), status, pages_fetched, attempts, retries, cursor, codes, expected_total)

    for _ in range(max_pages):
        if cursor in visited:
            return failed("CURSOR_LOOP")
        visited.add(cursor)
        response = None
        for attempt in range(1, retry_policy.max_attempts + 1):
            attempts += 1
            try:
                response = fetcher(cursor)
            except Exception:
                return failed("FETCH_ERROR")
            if (not isinstance(response, PageResponse) or type(response.status_code) is not int
                    or type(response.rate_limited) is not bool):
                return failed("INVALID_RESPONSE")
            limited = response.rate_limited is True or response.status_code == 429
            transient = response.status_code in {500, 502, 503, 504}
            if limited or transient:
                if attempt == retry_policy.max_attempts or wait is None:
                    return failed("RATE_LIMITED" if limited else "HTTP_RETRY_EXHAUSTED")
                try:
                    delay = _retry_delay(response, attempt, retry_policy)
                    if delay is None:
                        return failed("RATE_LIMITED" if limited else "HTTP_RETRY_EXHAUSTED")
                    wait(delay)
                except Exception:
                    return failed("BACKOFF_ERROR")
                retries += 1
                continue
            if not 200 <= response.status_code < 300:
                return failed("HTTP_STATUS")
            break
        assert response is not None
        try:
            page = parser(response)
        except Exception:
            return failed("PARSER_ERROR")
        if not isinstance(page, ParsedPage):
            return failed("INVALID_PARSED_PAGE")
        if (not isinstance(page.items, tuple) or any(not isinstance(item, dict) for item in page.items)
                or not isinstance(page.errors, tuple)
                or any(not isinstance(error, str) or error not in _PARSE_ERRORS for error in page.errors)):
            return failed("INVALID_PARSED_PAGE")
        pages_fetched += 1
        items.extend(page.items)
        if page.errors:
            return failed(page.errors)
        if page.total_count is not None:
            if type(page.total_count) is not int or page.total_count < 0:
                return failed("INVALID_TOTAL_COUNT")
            if expected_total is not None and page.total_count != expected_total:
                return failed("INCONSISTENT_TOTAL_COUNT")
            expected_total = page.total_count
        if identity_key is not None:
            for item in page.items:
                identity = item.get(identity_key)
                if not ((isinstance(identity, str) and bool(identity) and len(identity) <= 256)
                        or (type(identity) is int and identity >= 0)):
                    return failed("INVALID_RECORD_ID")
                if identity in identities:
                    return failed("DUPLICATE_RECORD_ID")
                identities.add(identity)
        if expected_total is not None and len(items) > expected_total:
            return failed("TOTAL_COUNT_MISMATCH")
        if type(page.has_next) is not bool:
            return failed("INVALID_PAGE_INFO")
        if not page.has_next and page.next_cursor is not None:
            return failed("INVALID_PAGE_INFO")
        completed_pages += 1
        if not page.has_next:
            if expected_total is not None and len(items) != expected_total:
                return failed("TOTAL_COUNT_MISMATCH")
            return PaginationResult(
                tuple(items), CollectionStatus.COMPLETE, pages_fetched, attempts, retries, None,
                total_count=expected_total,
            )
        if not isinstance(page.next_cursor, str) or not page.next_cursor.strip():
            return failed("MISSING_NEXT_CURSOR")
        cursor = page.next_cursor
        if cursor in visited:
            return failed("CURSOR_LOOP")
    return failed("PAGE_LIMIT_EXCEEDED")
