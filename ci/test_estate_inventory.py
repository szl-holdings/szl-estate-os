from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import estate_inventory as inventory


def row(name="owner/public", kind="repo", **fields):
    return {"full_name" if kind == "repo" else "id": name, "private": False, **fields}


class PublicInventoryTests(unittest.TestCase):
    def test_only_explicit_public_in_scope_rows_survive(self):
        for kind in ("repo", "model", "dataset"):
            for invalid in (
                row("owner/private-marker", kind, private=True),
                row("owner/unknown-marker", kind, private=None),
                row("owner/number-marker", kind, private=0),
                row("owner/string-marker", kind, private="false"),
                row("other/foreign-marker", kind),
                row("owner/name/extra-marker", kind),
                row("owner/\u212a-marker", kind),
                {}, None,
            ):
                with self.subTest(kind=kind, invalid=invalid):
                    result = inventory.collect_source("owner", kind, fetch=lambda _: ([row(kind=kind), invalid], ""))
                    self.assertEqual(result["status"], "PARTIAL")
                    self.assertEqual(len(result["records"]), 1)
                    self.assertNotIn("marker", json.dumps(result))

    def test_projection_drops_bodies_config_and_unknown_counters(self):
        value = row(description="secret-marker", cardData={"token": "secret-marker"},
                    stargazers_count=True, archived=False, fork=False)
        projected = inventory.public_record(value, "owner", "repo")
        self.assertEqual(set(projected), {"id", "kind", "visibility", "stargazers_count", "archived", "fork"})
        self.assertIsNone(projected["stargazers_count"])
        self.assertNotIn("secret-marker", json.dumps(projected))
        hf = inventory.public_record(row(kind="model", downloads=-1), "owner", "model")
        self.assertIsNone(hf["downloads"])
        self.assertIsNone(hf["likes"])

    def test_empty_observation_does_not_claim_complete_estate(self):
        result = inventory.build_inventory("owner", "owner", fetch=lambda _: ([], ""))
        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(result["scope"], "PUBLIC_ONLY")
        self.assertEqual(result["private_inventory"], "UNAVAILABLE")
        self.assertFalse(result["complete_estate"])
        self.assertFalse(result["runtime_verified"])

    def test_cross_source_failure_preserves_successful_public_rows(self):
        def fetch(url):
            if urlsplit(url).hostname == "api.github.com":
                raise inventory.InventoryError("HTTP_403")
            return [row(kind="model")], ""
        result = inventory.build_inventory("owner", "owner", fetch=fetch)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["summary"], {"repo_count": 0, "model_count": 1, "dataset_count": 1})
        self.assertEqual(result["sources"][0]["errors"], ["HTTP_403"])

    def test_bounded_pagination_retains_safe_partial_results(self):
        def fetch(url):
            return [row(kind="model")], f'<{url}&cursor=2>; rel="next"'
        result = inventory.collect_source("owner", "model", fetch=fetch, max_pages=1)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse(result["pagination_exhausted"])
        self.assertEqual(result["errors"], ["PAGE_LIMIT_REACHED"])
        self.assertEqual(len(result["records"]), 1)

    def test_pagination_cycle_is_partial(self):
        result = inventory.collect_source("owner", "model", fetch=lambda url: ([row(kind="model")], f'<{url}>; rel="next"'))
        self.assertEqual(result["errors"], ["PAGINATION_CYCLE"])
        self.assertEqual(result["pages_observed"], 1)

    def test_duplicate_rows_are_not_double_counted(self):
        result = inventory.collect_source("owner", "repo", fetch=lambda _: ([row(), row("OWNER/PUBLIC")], ""))
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["errors"], ["DUPLICATE_RECORD"])
        self.assertEqual(len(result["records"]), 1)

    def test_valid_pagination_is_exhausted(self):
        seen = []
        def fetch(url):
            seen.append(url)
            if len(seen) == 1:
                return [row("owner/one", "model")], f'<{url}&cursor=next1>; rel="next"'
            return [row("owner/two", "model")], ""
        result = inventory.collect_source("owner", "model", fetch=fetch)
        self.assertEqual(result["status"], "MEASURED")
        self.assertTrue(result["pagination_exhausted"])
        self.assertEqual(result["pages_observed"], 2)
        self.assertEqual(len(result["records"]), 2)

    def test_github_pagination_uses_original_scoped_endpoint(self):
        seen = []
        def fetch(url):
            seen.append(url)
            if len(seen) == 1:
                return [row(f"owner/repo-{index}") for index in range(100)], '<https://other.test/>; rel="next"'
            return [row("owner/.github")], ""
        result = inventory.collect_source("owner", "repo", fetch=fetch)
        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(len(result["records"]), 101)
        self.assertEqual(seen[1], seen[0] + "&page=2")
        self.assertIn("type=public", seen[1])

    def test_github_full_pages_hit_bound_instead_of_claiming_exhaustion(self):
        result = inventory.collect_source("owner", "repo", max_pages=1,
            fetch=lambda _: ([row(f"owner/repo-{index}") for index in range(100)], ""))
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["errors"], ["PAGE_LIMIT_REACHED"])

    def test_pagination_cannot_change_origin_endpoint_or_scope(self):
        initial = "https://huggingface.co/api/models?author=owner&limit=100"
        for url in (
            "http://huggingface.co/api/models?author=owner", "https://evil.test/api/models?author=owner",
            "https://huggingface.co/api/datasets?author=owner", "https://huggingface.co/api/models?author=other",
            "https://huggingface.co/api/models?cursor=1", "https://user:password@huggingface.co/api/models?author=owner",
            "https://huggingface.co:443/api/models?author=owner", "https://huggingface.co/api/models?author=owner#x",
            "https://huggingface.co/api/models?author=owner&author=other", initial + "\n",
            "https://[malformed/api/models?author=owner",
        ):
            with self.subTest(url=url), self.assertRaises(inventory.InventoryError):
                inventory.next_page_url(f'<{url}>; rel="next"', initial, initial)

    def test_malformed_next_link_retains_partial_snapshot(self):
        result = inventory.collect_source("owner", "model", fetch=lambda _: (
            [row(kind="model")], '<https://[malformed>; rel="next"'))
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["errors"], ["INVALID_PAGINATION"])
        self.assertEqual(len(result["records"]), 1)

    def test_non_list_page_is_partial(self):
        result = inventory.collect_source("owner", "repo", fetch=lambda _: ({"message": "sensitive"}, ""))
        self.assertEqual(result["errors"], ["INVALID_PAGE_SHAPE"])
        self.assertNotIn("sensitive", json.dumps(result))

    def test_organization_cannot_inject_url(self):
        for org in ("../owner", "owner?x=1", "owner/name", "\u212a", ""):
            with self.subTest(org=org), self.assertRaises(ValueError):
                inventory.build_inventory(org, "owner", fetch=lambda _: ([], ""))

    def test_transport_never_uses_ambient_credentials(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b"[]"
        response.headers = {}
        opener = MagicMock()
        opener.open.return_value = response
        with patch.dict(os.environ, {"GITHUB_TOKEN": "secret-marker", "HF_TOKEN": "secret-marker"}), patch.object(inventory, "build_opener", return_value=opener):
            self.assertEqual(inventory.get_public_page("https://huggingface.co/api/models"), ([], ""))
        request = opener.open.call_args.args[0]
        self.assertNotIn("Authorization", request.headers)
        self.assertNotIn("secret-marker", str(request.headers))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
        response.read.assert_called_once_with(inventory.MAX_RESPONSE_BYTES + 1)

    def test_transport_errors_are_sanitized(self):
        for error, expected in (
            (HTTPError("https://secret-marker", 403, "secret-marker", {}, None), "HTTP_403"),
            (URLError("secret-marker"), "NETWORK_ERROR"),
        ):
            with self.subTest(expected=expected), patch.object(inventory, "build_opener") as build:
                build.return_value.open.side_effect = error
                with self.assertRaises(inventory.InventoryError) as caught:
                    inventory.get_public_page("https://huggingface.co/api/models")
                self.assertEqual(str(caught.exception), expected)

    def test_transport_rejects_invalid_json_shape_and_size(self):
        for payload, expected in ((b"not-json", "INVALID_JSON"), (b"{}", "INVALID_PAGE_SHAPE"), (b"x" * (inventory.MAX_RESPONSE_BYTES + 1), "RESPONSE_TOO_LARGE")):
            with self.subTest(expected=expected), patch.object(inventory, "build_opener") as build:
                response = build.return_value.open.return_value.__enter__.return_value
                response.status, response.read.return_value = 200, payload
                with self.assertRaises(inventory.InventoryError) as caught:
                    inventory.get_public_page("https://huggingface.co/api/models")
                self.assertEqual(str(caught.exception), expected)

    def test_redirect_handler_refuses_new_origin(self):
        self.assertIsNone(inventory.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test"))

    def test_partial_cli_writes_packet_but_exits_nonzero(self):
        for status, expected in (("PARTIAL", 1), ("MEASURED", 0)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary, patch.object(inventory, "build_inventory", return_value={"status": status, "scope": "PUBLIC_ONLY", "summary": {}}):
                target = Path(temporary) / "snapshot.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(inventory.main(["--out", str(target)]), expected)
                self.assertEqual(json.loads(target.read_text())["status"], status)


class WorkflowContractTests(unittest.TestCase):
    def test_housekeeping_uses_pinned_read_only_exact_artifact_contract(self):
        workflow = (ROOT / ".github/workflows/estate_housekeeping.yml").read_text()
        pins = re.findall(r"uses:\s*([^\s]+)", workflow)
        self.assertEqual(len(pins), 3)
        for pin in pins:
            self.assertRegex(pin, r"^[\w/-]+@[0-9a-f]{40}$")
        for forbidden in ("secrets.", "contents: write", "git push", "git commit", "pip install", "path: outputs/\n"):
            self.assertNotIn(forbidden, workflow)
        for required in ("contents: read", "persist-credentials: false", "timeout-minutes: 20", "if: always()", "path: outputs/housekeeping/estate_state.json", "if-no-files-found: error", "retention-days: 30"):
            self.assertIn(required, workflow)
        self.assertIn("python ci/test_estate_inventory.py -v", (ROOT / ".github/workflows/ci.yml").read_text())


if __name__ == "__main__":
    unittest.main()
