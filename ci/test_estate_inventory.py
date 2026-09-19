"""Network-free regression cases for the existing registry inventory entrypoint."""
from __future__ import annotations

import contextlib
import hashlib
import http.client
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import estate_inventory as inventory  # noqa: E402

GH = "https://api.github.com/orgs/example/repos?per_page=100"
HF = "https://huggingface.co/api/models?author=example&limit=100"


class Response:
    def __init__(self, body, headers=None):
        self.body = body
        self.headers = headers or {}
        self.read_limits = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        self.read_limits.append(limit)
        return self.body[:limit]


def listing_fixture(overrides=None):
    data = {
        "repos": [{"id": 1, "name": "example", "full_name": "example/example"}],
        "models": [{"id": "example/model", "sha": "a" * 40}],
        "datasets": [{"id": "example/dataset", "sha": "b" * 40}],
        "spaces": [{"id": "example/space", "sha": "c" * 40, "sdk": "gradio"}],
        "collections": [{"slug": "example/collection-012345", "title": "Examples"}],
    }
    data.update(overrides or {})
    calls = []

    def fetch(url, token):
        calls.append((url, token))
        value = data[urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]]
        if isinstance(value, Exception):
            raise value
        return value, {}

    return fetch, calls


class NetworkBlockedCase(unittest.TestCase):
    def setUp(self):
        self.network = patch.object(inventory.urllib.request, "build_opener", side_effect=AssertionError("Live network is forbidden in this suite"))
        self.network.start()
        self.addCleanup(self.network.stop)


class PaginationTests(NetworkBlockedCase):
    def test_follows_hf_cursor_link_and_preserves_query(self):
        second = "https://huggingface.co/api/models?author=example&cursor=opaque%2Fnext&limit=100"
        fetch = Mock(side_effect=[([{"id": "example/a"}], {"Link": f'<{second}>; rel="next"'}), ([{"id": "example/b"}], {})])
        items, coverage = inventory.collect_pages(HF, "hf-test", fetch=fetch)
        self.assertEqual([item["id"] for item in items], ["example/a", "example/b"])
        self.assertEqual(fetch.call_args_list[1].args, (second, "hf-test"))
        self.assertTrue(coverage["complete"])
        self.assertEqual(coverage["pages"], 2)

    def test_relative_next_link(self):
        fetch = Mock(side_effect=[([{"id": 1}], {"link": '<?page=2>; rel="next"'}), ([{"id": 2}], {})])
        _, coverage = inventory.collect_pages(GH, "gh-test", fetch=fetch)
        self.assertEqual(fetch.call_args_list[1].args[0], "https://api.github.com/orgs/example/repos?page=2")
        self.assertTrue(coverage["complete"])

    def test_good_page_is_preserved_after_http_failure(self):
        fetch = Mock(side_effect=[([{"id": 1}], {"link": '<?page=2>; rel="next"'}), inventory.InventoryError("HTTP_403")])
        items, coverage = inventory.collect_pages(GH, "", fetch=fetch)
        self.assertEqual(items, [{"id": 1}])
        self.assertEqual(coverage["status"], "PARTIAL")
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["errors"][0]["code"], "HTTP_403")

    def test_malformed_cursor_url_preserves_collected_page(self):
        fetch = Mock(return_value=([{"id": 1}], {"link": '<https://[broken/x>; rel="next"'}))
        items, coverage = inventory.collect_pages(GH, "gh-test", fetch=fetch)
        self.assertEqual(items, [{"id": 1}])
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["errors"][0]["code"], "UNTRUSTED_API_URL")
        self.assertEqual(fetch.call_count, 1)

    def test_cursor_cycle_stops_without_second_request(self):
        fetch = Mock(return_value=([{"id": 1}], {"link": f'<{GH}>; rel="next"'}))
        items, coverage = inventory.collect_pages(GH, "", fetch=fetch)
        self.assertEqual(items, [{"id": 1}])
        self.assertEqual(coverage["errors"][0]["code"], "PAGINATION_CYCLE")
        self.assertEqual(fetch.call_count, 1)

    def test_duplicate_identity_does_not_inflate_count(self):
        fetch = Mock(side_effect=[([{"id": 1}], {"link": '<?page=2>; rel="next"'}), ([{"id": 1}], {})])
        items, coverage = inventory.collect_pages(GH, "", fetch=fetch)
        self.assertEqual(len(items), 1)
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["errors"][0]["code"], "DUPLICATE_OR_EMPTY_ID")

    def test_page_budget_is_a_partial_result(self):
        fetch = Mock(return_value=([{"id": 1}], {"link": '<?page=2>; rel="next"'}))
        _, coverage = inventory.collect_pages(GH, "", fetch=fetch, max_pages=1)
        self.assertEqual(coverage["errors"][0]["code"], "PAGE_LIMIT")
        self.assertFalse(coverage["complete"])
        self.assertEqual(fetch.call_count, 1)

    def test_non_list_payload_does_not_become_empty_complete(self):
        _, coverage = inventory.collect_pages(GH, "", fetch=Mock(return_value=({"message": "not a list"}, {})))
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["errors"][0]["code"], "LIST_SHAPE_INVALID")

    def test_missing_empty_and_boolean_ids_fail_closed(self):
        for record in ({}, {"id": ""}, {"id": True}, {"id": False}, {"id": None}):
            with self.subTest(record=record):
                items, coverage = inventory.collect_pages(GH, "", fetch=Mock(return_value=([record], {})))
                self.assertFalse(coverage["complete"])
                self.assertEqual(items, [])

    def test_valid_empty_listing_is_distinct_from_failure(self):
        items, coverage = inventory.collect_pages(GH, "", fetch=Mock(return_value=([], {})))
        self.assertEqual(items, [])
        self.assertTrue(coverage["complete"])
        self.assertEqual(coverage["errors"], [])

    def test_link_relations_can_include_multiple_tokens(self):
        value = f'<{HF}>; rel="prev", <{HF}&cursor=2>; rel="next alternate"'
        self.assertEqual(inventory.next_link(value), HF + "&cursor=2")

    def test_malformed_and_ambiguous_links_are_rejected(self):
        for value in ("not a link", f'<{HF}>; rel=', f'<{HF}>; rel="next', f'<{HF}>; rel="next", <{HF}&page=2>; rel="next"'):
            with self.subTest(value=value):
                with self.assertRaises(inventory.InventoryError):
                    inventory.next_link(value)


class CredentialAndNetworkTests(NetworkBlockedCase):
    def test_untrusted_initial_urls_never_reach_opener(self):
        for url in (
            "http://api.github.com/repos", "https://api.github.com.evil.example/repos",
            "https://huggingface.co@evil.example/api/models", "https://user:pass@huggingface.co/api/models",
            "https://api.github.com:444/repos", "https://api.github.com/repos#fragment",
            "https://api.github.com:bad/repos", "file:///etc/passwd",
        ):
            with self.subTest(url=url), self.assertRaises(inventory.InventoryError):
                inventory.request_json(url, "must-stay-local")

    def test_provider_and_external_cross_origin_pagination_never_receives_token(self):
        for next_url in (HF, "https://evil.example/collect", "https://api.github.com:444/x"):
            with self.subTest(next_url=next_url):
                fetch = Mock(return_value=([{"id": 1}], {"link": f'<{next_url}>; rel="next"'}))
                items, coverage = inventory.collect_pages(GH, "gh-test-secret", fetch=fetch)
                self.assertEqual(items, [{"id": 1}])
                self.assertEqual(fetch.call_count, 1)
                self.assertFalse(coverage["complete"])
                self.assertNotIn("gh-test-secret", json.dumps(coverage))
                self.assertEqual(coverage["errors"][0]["code"], "UNTRUSTED_API_URL")

    def test_redirect_handler_rejects_even_same_origin(self):
        for target in (GH + "&page=2", HF, "https://evil.example/x"):
            with self.subTest(target=target), self.assertRaisesRegex(inventory.InventoryError, "API_REDIRECT_REJECTED"):
                inventory.NoRedirect().redirect_request(None, None, 302, "Found", {}, target)

    def test_request_attaches_token_only_after_url_validation(self):
        response = Response(b"[]", {"Link": ""})
        opener = Mock()
        opener.open.return_value = response
        with patch.object(inventory.urllib.request, "build_opener", return_value=opener) as build:
            data, headers = inventory.request_json(GH, "gh-test", timeout=7)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, GH)
        self.assertEqual(request.get_header("Authorization"), "Bearer gh-test")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 7)
        self.assertIsInstance(build.call_args.args[0], inventory.NoRedirect)
        self.assertEqual(data, [])
        self.assertEqual(headers, {"link": ""})
        self.assertEqual(response.read_limits, [inventory.MAX_BYTES + 1])

    def test_http_error_response_body_and_url_are_not_disclosed(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError(GH + "&token=do-not-log", 403, "secret response", {}, io.BytesIO(b"secret body"))
        with patch.object(inventory.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.request_json(GH, "gh-test")
        self.assertEqual(str(raised.exception), "HTTP_403")

    def test_response_byte_budget(self):
        opener = Mock()
        opener.open.return_value = Response(b"[123456789]")
        with patch.object(inventory, "MAX_BYTES", 5), patch.object(inventory.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(inventory.InventoryError, "RESPONSE_TOO_LARGE"):
                inventory.request_json(GH)

    def test_invalid_json_is_a_safe_error(self):
        opener = Mock()
        opener.open.return_value = Response(b"secret invalid response")
        with patch.object(inventory.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(inventory.InventoryError, "INVALID_JSON"):
                inventory.request_json(GH)

    def test_truncated_network_body_is_a_safe_error(self):
        opener = Mock()
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.side_effect = http.client.IncompleteRead(b"private-body-fragment", 100)
        opener.open.return_value = response
        with patch.object(inventory.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(inventory.InventoryError) as raised:
                inventory.request_json(GH)
        self.assertEqual(str(raised.exception), "NETWORK_ERROR")


class InventorySemanticsTests(NetworkBlockedCase):
    def test_all_five_lists_and_provider_credentials_are_separate(self):
        fetch, calls = listing_fixture()
        result = inventory.build_inventory("example", "example", "gh-test", "hf-test", fetch=fetch)
        self.assertEqual(set(result["coverage"]), {"github", "models", "datasets", "spaces", "collections"})
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[0][1], "gh-test")
        self.assertTrue(all(token == "hf-test" for _, token in calls[1:]))
        self.assertEqual({a["kind"] for a in result["hf_assets"]}, {"model", "dataset", "space"})
        self.assertEqual(result["summary"]["total_collections"], 1)
        self.assertEqual(result["status"], "COMPLETE_VISIBLE_LISTING")
        self.assertEqual(result["signer_state"], "UNSIGNED")
        self.assertEqual(result["scope"]["github"], "AUTHENTICATED_VISIBILITY_UNKNOWN")

    def test_unavailable_list_preserves_four_other_collections(self):
        fetch, calls = listing_fixture({"models": inventory.InventoryError("HTTP_401")})
        result = inventory.build_inventory("example", "example", "", "", fetch=fetch)
        self.assertEqual(len(calls), 5)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["coverage"]["models"]["errors"][0]["code"], "HTTP_401")
        self.assertEqual(result["summary"]["total_hf_assets"], 2)
        self.assertEqual(result["summary"]["total_repos"], 1)
        self.assertEqual(result["summary"]["total_collections"], 1)

    def test_missing_metrics_are_null_and_not_counted_as_zero(self):
        fetch, _ = listing_fixture({"datasets": [{"id": "example/dataset", "downloads": 0}]})
        result = inventory.build_inventory("example", "example", "", "", fetch=fetch)
        by_kind = {item["kind"]: item for item in result["hf_assets"]}
        self.assertIsNone(by_kind["model"]["downloads"])
        self.assertIsNone(by_kind["space"]["downloads"])
        self.assertIsNone(by_kind["model"]["likes"])
        self.assertEqual(result["summary"]["zero_download_hf_assets"], 1)
        self.assertEqual(result["summary"]["download_metric_unavailable"], 1)
        self.assertIsNone(result["collections"][0]["items_count"])

    def test_canonical_homepage_cannot_retire_active_repository(self):
        result = inventory.github_record({"id": 1, "name": "szl-estate-os", "html_url": "https://github.com/szl-holdings/szl-estate-os", "homepage": "https://a-11-oy.com", "description": "Canonical SZL estate"})
        self.assertEqual(result["status"], "UNCLASSIFIED")
        self.assertIsNone(result["canonical_successor"])
        self.assertEqual(result["runtime_state"], "UNVERIFIED")

    def test_archived_provider_flag_precedes_local_flagship_taxonomy(self):
        result = inventory.github_record({"name": "a11oy", "archived": True})
        self.assertEqual(result["status"], "ARCHIVED")
        self.assertEqual(result["status_basis"], "PROVIDER_ARCHIVED_FLAG")

    def test_provider_running_stage_does_not_claim_runtime_readiness(self):
        result = inventory.hf_record({"id": "example/space", "runtime": {"stage": "RUNNING"}}, "space")
        self.assertEqual(result["provider_runtime_stage"], "RUNNING")
        self.assertEqual(result["runtime_state"], "UNVERIFIED")
        self.assertEqual(result["publication_eligibility"], "UNVERIFIED")
        self.assertEqual(result["artifact_classification"], "UNVERIFIED")

    def test_invalid_owner_stops_before_any_request(self):
        fetch = Mock()
        with self.assertRaisesRegex(inventory.InventoryError, "INVALID_ORGANIZATION"):
            inventory.build_inventory("example/../../x", "example", "", "", fetch=fetch)
        fetch.assert_not_called()

    def test_malformed_provider_metadata_preserves_other_lists(self):
        cases = [
            ("repos", [{"id": 1, "name": "example", "license": "malformed"}], "github"),
            ("spaces", [{"id": "example/space", "runtime": "malformed"}], "spaces"),
            ("collections", [{"slug": 42, "title": "Invalid"}], "collections"),
        ]
        for key, rows, coverage_key in cases:
            with self.subTest(surface=key):
                fetch, calls = listing_fixture({key: rows})
                result = inventory.build_inventory("example", "example", "", "", fetch=fetch)
                self.assertEqual(result["status"], "PARTIAL")
                self.assertFalse(result["coverage"][coverage_key]["complete"])
                self.assertTrue(result["coverage"][coverage_key]["errors"])
                self.assertEqual(len(calls), 5)


class SerializationAndCliTests(NetworkBlockedCase):
    def test_sidecar_hash_matches_exact_written_bytes_including_newline(self):
        value = {"value": "café", "unknown": None}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "estate.json"
            digest = inventory.write_inventory(path, value)
            payload = path.read_bytes()
            self.assertTrue(payload.endswith(b"\n"))
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
            self.assertNotEqual(hashlib.sha256(payload.rstrip(b"\n")).hexdigest(), digest)
            self.assertEqual(path.with_suffix(".json.sha256").read_text(), f"{digest}  estate.json\n")
            self.assertEqual(json.loads(payload), value)

    def test_json_bytes_are_deterministic(self):
        self.assertEqual(inventory.canonical_bytes({"b": 2, "a": 1}), inventory.canonical_bytes({"a": 1, "b": 2}))
        with self.assertRaises(ValueError):
            inventory.canonical_bytes({"bad": float("nan")})

    def test_partial_cli_returns_nonzero_and_writes_verifiable_artifact(self):
        fetch, _ = listing_fixture({"models": inventory.InventoryError("HTTP_403")})
        value = inventory.build_inventory("example", "example", "", "", fetch=fetch)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            output = io.StringIO()
            with patch.object(inventory, "build_inventory", return_value=value), contextlib.redirect_stdout(output):
                code = inventory.main(["--out", str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "PARTIAL")
            self.assertEqual(json.loads(path.read_text())["status"], "PARTIAL")
            self.assertEqual(path.with_suffix(".json.sha256").read_text().split()[0], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_complete_cli_zero_still_reports_unsigned_visibility(self):
        fetch, _ = listing_fixture()
        value = inventory.build_inventory("example", "example", "", "", fetch=fetch)
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with patch.object(inventory, "build_inventory", return_value=value), contextlib.redirect_stdout(output):
                code = inventory.main(["--out", str(Path(temporary) / "result.json")])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["signer_state"], "UNSIGNED")

    def test_cli_rejects_invalid_page_limit(self):
        for limit in ("0", "1001", "-1"):
            with self.subTest(limit=limit), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                inventory.main(["--max-pages", limit])
            self.assertEqual(raised.exception.code, 2)

    def test_cli_selects_tokens_without_logging_them(self):
        fetch, _ = listing_fixture()
        value = inventory.build_inventory("example", "example", "", "", fetch=fetch)
        env = {"GH_TOKEN": "gh-test-private", "GITHUB_TOKEN": "secondary-gh", "HF_TOKEN": "hf-test-private", "HUGGING_FACE_HUB_TOKEN": "secondary-hf"}
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch.object(inventory, "build_inventory", return_value=value) as build, contextlib.redirect_stdout(output):
                self.assertEqual(inventory.main(["--out", str(Path(temporary) / "result.json")]), 0)
            self.assertEqual(build.call_args.args[2:], ("gh-test-private", "hf-test-private"))
            self.assertNotIn("gh-test-private", output.getvalue())
            self.assertNotIn("hf-test-private", output.getvalue())


if __name__ == "__main__":
    unittest.main()
