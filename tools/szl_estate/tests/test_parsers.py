"""Synthetic response and injected-fetcher tests; entirely offline."""

from __future__ import annotations

import pytest

from szl_estate.parsers import (
    CollectionStatus,
    CountStatus,
    PageResponse,
    ParsedPage,
    RetryPolicy,
    collect_pages,
    parse_comment_count,
    parse_github_graphql_page,
    parse_rest_page,
)


def rest(response):
    return parse_rest_page(response.payload, next_cursor=response.next_cursor)


def graphql_payload(nodes, *, has_next=False, cursor=None, total_count=None):
    return {"data": {"organization": {"repositories": {
        "nodes": nodes,
        "totalCount": total_count,
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
    }}}}


def graphql(response):
    return parse_github_graphql_page(response.payload, connection_path=("organization", "repositories"))


def collect(responses, parser=rest, **kwargs):
    observed = []
    iterator = iter(responses)

    def fetch(cursor):
        observed.append(cursor)
        return next(iterator)

    return collect_pages(fetch, parser, **kwargs), observed


@pytest.mark.parametrize("raw,count,status", [
    (None, None, CountStatus.UNKNOWN),
    (0, 0, CountStatus.KNOWN),
    (5, 5, CountStatus.KNOWN),
    ([], 0, CountStatus.KNOWN),
    ([{}, {}], 2, CountStatus.KNOWN),
    ({"totalCount": 3}, 3, CountStatus.KNOWN),
    ({}, None, CountStatus.UNKNOWN),
    ({"nodes": []}, None, CountStatus.UNKNOWN),
    ({"totalCount": None}, None, CountStatus.UNKNOWN),
    (True, None, CountStatus.INVALID),
    (False, None, CountStatus.INVALID),
    (-1, None, CountStatus.INVALID),
    ({"totalCount": -1}, None, CountStatus.INVALID),
    ({"totalCount": True}, None, CountStatus.INVALID),
    ("5", None, CountStatus.INVALID),
    (5.0, None, CountStatus.INVALID),
])
def test_comment_shapes_keep_unknown_and_invalid_distinct(raw, count, status):
    result = parse_comment_count(raw)
    assert result.count == count
    assert result.status is status


def test_absent_comments_are_unknown_not_zero():
    assert parse_comment_count().status is CountStatus.UNKNOWN


def test_rest_array_and_explicit_object_collection():
    assert parse_rest_page([{"id": 1}]).items == ({"id": 1},)
    page = parse_rest_page({"items": [{"id": 1}], "total_count": 1}, collection_key="items")
    assert page.valid
    assert page.total_count == 1
    assert page.items == ({"id": 1},)


@pytest.mark.parametrize("payload,kwargs,code", [
    ({"items": []}, {}, "OBJECT_COLLECTION_KEY_REQUIRED"),
    ({"message": "private response text"}, {"collection_key": "items"}, "MISSING_COLLECTION"),
    ({"items": {}}, {"collection_key": "items"}, "INVALID_COLLECTION_SHAPE"),
    ({"items": []}, {"collection_key": []}, "INVALID_COLLECTION_KEY"),
    (None, {}, "INVALID_PAGE_SHAPE"),
    ([1], {}, "INVALID_RECORD_SHAPE"),
    ({"items": [], "total_count": True}, {"collection_key": "items"}, "INVALID_TOTAL_COUNT"),
    ([], {"next_cursor": ""}, "INVALID_CURSOR"),
    ({"items": [], "errors": {"message": "private"}}, {"collection_key": "items"}, "API_ERRORS"),
    ({"items": [], "error": "unauthorized"}, {"collection_key": "items"}, "API_ERRORS"),
])
def test_invalid_rest_shapes_never_parse_as_success(payload, kwargs, code):
    assert code in parse_rest_page(payload, **kwargs).errors


def test_mixed_record_shapes_retain_partial_items():
    page = parse_rest_page([{"id": 1}, None])
    assert page.items == ({"id": 1},)
    assert not page.valid


def test_graphql_nodes_page_info_and_total_count():
    page = graphql(PageResponse(graphql_payload([{"id": "node-1"}], has_next=True, cursor="opaque", total_count=2)))
    assert page.valid
    assert page.items == ({"id": "node-1"},)
    assert page.next_cursor == "opaque"
    assert page.has_next is True
    assert page.total_count == 2


def test_graphql_partial_data_with_errors_never_succeeds_or_echoes_errors():
    payload = graphql_payload([{"id": "node-1"}])
    payload["errors"] = [{"message": "private-secret-response"}]
    page = graphql(PageResponse(payload))
    assert page.items == ({"id": "node-1"},)
    assert page.errors == ("GRAPHQL_ERRORS",)
    result, _ = collect([PageResponse(payload)], parser=graphql)
    assert result.status is CollectionStatus.PARTIAL
    assert not result.complete
    assert "private-secret-response" not in str(result)


@pytest.mark.parametrize("payload,code", [
    ({"errors": [{"message": "secret"}]}, "MISSING_CONNECTION"),
    ({"data": {"organization": None}}, "MISSING_CONNECTION"),
    (graphql_payload(None), "INVALID_COLLECTION_SHAPE"),
    (graphql_payload([], has_next="false"), "INVALID_PAGE_INFO"),
    (graphql_payload([], has_next=True), "MISSING_NEXT_CURSOR"),
    (graphql_payload([], has_next=True, cursor=""), "INVALID_CURSOR"),
    (graphql_payload([], total_count=-1), "INVALID_TOTAL_COUNT"),
])
def test_graphql_unknown_or_malformed_fields_fail_closed(payload, code):
    assert code in graphql(PageResponse(payload)).errors


def test_graphql_connection_path_must_be_explicit_sequence():
    page = parse_github_graphql_page(graphql_payload([]), connection_path="organization.repositories")
    assert page.errors == ("INVALID_CONNECTION_PATH",)


def test_two_pages_with_validated_next_cursor_complete():
    result, cursors = collect([
        PageResponse([{"id": 1}], next_cursor="page-2"),
        PageResponse([{"id": 2}]),
    ], identity_key="id")
    assert result.complete
    assert result.items == ({"id": 1}, {"id": 2})
    assert cursors == [None, "page-2"]
    assert result.pages_fetched == result.attempts == 2
    assert result.next_cursor is None


def test_valid_empty_terminal_collection_is_complete():
    result, _ = collect([PageResponse([])])
    assert result.complete
    assert result.items == ()


def test_http_auth_failure_is_inaccessible_without_false_success():
    result, cursors = collect([PageResponse({"message": "private auth error"}, status_code=403)])
    assert result.status is CollectionStatus.INACCESSIBLE
    assert result.errors == ("HTTP_STATUS",)
    assert not result.complete
    assert cursors == [None]
    assert "private auth error" not in str(result)


def test_failed_second_page_preserves_records_and_resume_cursor():
    result, _ = collect([
        PageResponse([{"id": 1}], next_cursor="page-2"),
        PageResponse({}, status_code=401),
    ])
    assert result.status is CollectionStatus.PARTIAL
    assert result.items == ({"id": 1},)
    assert result.next_cursor == "page-2"
    assert not result.complete


def test_empty_first_page_followed_by_failure_is_still_partial():
    result, _ = collect([PageResponse([], next_cursor="next"), PageResponse({}, status_code=403)])
    assert result.status is CollectionStatus.PARTIAL


def test_cursor_loop_is_bounded_and_never_complete():
    result, cursors = collect([
        PageResponse([{"id": 1}], next_cursor="same"),
        PageResponse([{"id": 2}], next_cursor="same"),
    ])
    assert cursors == [None, "same"]
    assert result.errors == ("CURSOR_LOOP",)
    assert result.status is CollectionStatus.PARTIAL


def test_max_pages_limit_has_a_resumable_cursor():
    result, cursors = collect([PageResponse([{"id": 1}], next_cursor="next")], max_pages=1)
    assert result.errors == ("PAGE_LIMIT_EXCEEDED",)
    assert result.next_cursor == "next"
    assert cursors == [None]
    assert not result.complete


def test_rate_limit_without_injected_wait_does_not_spin():
    result, cursors = collect([PageResponse({}, status_code=429)])
    assert result.status is CollectionStatus.INACCESSIBLE
    assert result.errors == ("RATE_LIMITED",)
    assert len(cursors) == 1


def test_provider_retry_after_within_budget_and_recovered_rate_limit():
    delays = []
    result, cursors = collect([
        PageResponse({}, status_code=429, retry_after_seconds=2),
        PageResponse({}, status_code=403, rate_limited=True),
        PageResponse([{"id": 1}]),
    ], wait=delays.append)
    assert result.complete
    assert result.retries == 2
    assert result.attempts == 3
    assert cursors == [None, None, None]
    assert delays == [2.0, 0.5]


@pytest.mark.parametrize("status,code", [(429, "RATE_LIMITED"), (503, "HTTP_RETRY_EXHAUSTED")])
def test_provider_retry_after_above_budget_stops_without_shortening_wait(status, code):
    delays = []
    result, cursors = collect([PageResponse({}, status_code=status, retry_after_seconds=120)], wait=delays.append)
    assert result.status is CollectionStatus.INACCESSIBLE
    assert result.errors == (code,)
    assert result.attempts == 1
    assert result.retries == 0
    assert cursors == [None]
    assert delays == []


def test_retry_after_above_budget_preserves_partial_records_and_failed_cursor():
    delays = []
    result, cursors = collect([
        PageResponse([{"id": 1}], next_cursor="failed-page"),
        PageResponse({}, status_code=429, retry_after_seconds=120),
    ], wait=delays.append)
    assert result.status is CollectionStatus.PARTIAL
    assert result.errors == ("RATE_LIMITED",)
    assert result.items == ({"id": 1},)
    assert result.next_cursor == "failed-page"
    assert cursors == [None, "failed-page"]
    assert delays == []


def test_retry_budget_exhaustion_cannot_be_success():
    delays = []
    result, _ = collect([PageResponse({}, status_code=503)] * 3, wait=delays.append)
    assert result.errors == ("HTTP_RETRY_EXHAUSTED",)
    assert result.status is CollectionStatus.INACCESSIBLE
    assert delays == [0.25, 0.5]
    assert result.retries == 2


def test_fetch_exception_message_is_not_retained():
    def fetch(_):
        raise RuntimeError("secret-token-in-exception")

    result = collect_pages(fetch, rest)
    assert result.errors == ("FETCH_ERROR",)
    assert "secret-token" not in str(result)


def test_parser_exception_message_is_not_retained():
    def parser(_):
        raise RuntimeError("secret-response-in-exception")

    result, _ = collect([PageResponse([])], parser=parser)
    assert result.errors == ("PARSER_ERROR",)
    assert "secret-response" not in str(result)


def test_backoff_exception_stops_retry_without_echo():
    def wait(_):
        raise RuntimeError("secret-backoff-exception")

    result, cursors = collect([PageResponse({}, status_code=429)], wait=wait)
    assert result.errors == ("BACKOFF_ERROR",)
    assert len(cursors) == 1
    assert "secret-backoff" not in str(result)


@pytest.mark.parametrize("response", [None, PageResponse([], status_code=True), PageResponse([], rate_limited="yes")])
def test_invalid_injected_transport_facts_never_succeed(response):
    result, _ = collect([response])
    assert result.errors == ("INVALID_RESPONSE",)
    assert not result.complete


def test_untrusted_parser_error_text_is_not_retained():
    result, _ = collect([PageResponse([])], parser=lambda _: ParsedPage(errors=("secret-response-text",)))
    assert result.errors == ("INVALID_PARSED_PAGE",)
    assert "secret-response" not in str(result)


def test_total_count_matches_only_after_complete_pagination():
    result, _ = collect([
        PageResponse(graphql_payload([{"id": "one"}], has_next=True, cursor="next", total_count=2)),
        PageResponse(graphql_payload([{"id": "two"}], total_count=2)),
    ], parser=graphql, identity_key="id")
    assert result.complete
    assert result.total_count == 2


def test_exhausted_graphql_nodes_below_total_count_are_partial():
    result, _ = collect([PageResponse(graphql_payload([{"id": "one"}, {"id": "two"}], total_count=3))], parser=graphql)
    assert result.status is CollectionStatus.PARTIAL
    assert result.errors == ("TOTAL_COUNT_MISMATCH",)
    assert not result.complete


def test_total_count_changed_during_pagination_is_partial():
    result, _ = collect([
        PageResponse(graphql_payload([{"id": "one"}], has_next=True, cursor="next", total_count=2)),
        PageResponse(graphql_payload([{"id": "two"}], total_count=3)),
    ], parser=graphql)
    assert result.errors == ("INCONSISTENT_TOTAL_COUNT",)
    assert result.total_count == 2
    assert not result.complete


def test_more_records_than_total_count_cannot_be_complete():
    result, _ = collect([PageResponse(graphql_payload([{"id": "one"}], total_count=0))], parser=graphql)
    assert result.errors == ("TOTAL_COUNT_MISMATCH",)


@pytest.mark.parametrize("count", [True, -1, "2"])
def test_invalid_injected_total_count_never_completes(count):
    result, _ = collect([PageResponse([])], parser=lambda _: ParsedPage(total_count=count))
    assert result.errors == ("INVALID_TOTAL_COUNT",)
    assert not result.complete


def test_duplicate_ids_cannot_fake_matching_total_count():
    result, _ = collect([
        PageResponse(graphql_payload([{"id": "one"}], has_next=True, cursor="next", total_count=2)),
        PageResponse(graphql_payload([{"id": "one"}], total_count=2)),
    ], parser=graphql, identity_key="id")
    assert result.errors == ("DUPLICATE_RECORD_ID",)
    assert not result.complete


@pytest.mark.parametrize("identity", [None, True, -1, [], ""])
def test_invalid_identity_is_not_silently_ignored(identity):
    result, _ = collect([PageResponse([{"id": identity}])], identity_key="id")
    assert result.errors == ("INVALID_RECORD_ID",)


@pytest.mark.parametrize("kwargs", [
    {"max_pages": 0}, {"max_pages": True}, {"initial_cursor": ""}, {"identity_key": ""},
    {"retry_policy": RetryPolicy(max_attempts=0)},
    {"retry_policy": RetryPolicy(base_delay_seconds=-1)},
    {"retry_policy": RetryPolicy(max_delay_seconds=float("inf"))},
])
def test_invalid_pagination_configuration_rejected_before_fetch(kwargs):
    calls = []
    with pytest.raises(ValueError):
        collect_pages(lambda cursor: calls.append(cursor), rest, **kwargs)
    assert calls == []
