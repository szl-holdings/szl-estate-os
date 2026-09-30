"""Offline failure, additive update, and issue idempotency contracts."""
import datetime as dt
import io
import json
import subprocess
import unittest
import urllib.error
from unittest.mock import patch

try:
    from . import github_ops as ops
except ImportError:
    import github_ops as ops


class FakeClient:
    def __init__(self, topics=None, *, drift=None, failure=False, keep_write=True, admin=True):
        self.topics = list(topics or [])
        self.drift, self.failure, self.keep_write, self.admin = drift, failure, keep_write, admin
        self.reads, self.writes = 0, []

    def request(self, path, method="GET", body=None):
        if method == "PUT":
            self.writes.append(body)
            if self.keep_write:
                self.topics = body["names"]
            if self.failure:
                raise ops.GitHubError("TRANSPORT_TIMEOUT")
            return {"names": self.topics}
        if path.endswith("/topics"):
            self.reads += 1
            if self.reads == 2 and self.drift is not None:
                self.topics = self.drift
            return {"names": self.topics.copy()}
        return {"archived": False, "disabled": False, "permissions": {"admin": self.admin}}


class TopicContracts(unittest.TestCase):
    def test_audit_is_read_only(self):
        client = FakeClient(["existing"])
        result = ops.topic_action(client, "szl-drift", ["model-monitoring"], False)
        self.assertEqual(result["status"], "PLANNED")
        self.assertEqual(client.writes, [])

    def test_apply_preserves_all_existing_topics(self):
        client = FakeClient(["custom", "existing"])
        result = ops.topic_action(client, "szl-drift", ["model-monitoring"], True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(set(client.topics), {"custom", "existing", "model-monitoring"})

    def test_repeat_does_not_write(self):
        client = FakeClient(["model-monitoring"])
        result = ops.topic_action(client, "szl-drift", ["model-monitoring"], True)
        self.assertEqual(result["status"], "ALREADY_CONVERGED")
        self.assertEqual(client.writes, [])

    def test_concurrent_drift_blocks_replace(self):
        client = FakeClient(["a"], drift=["a", "third-party"])
        result = ops.topic_action(client, "szl-drift", ["b"], True)
        self.assertEqual(result["reason"], "CONCURRENT_DRIFT")
        self.assertEqual(client.writes, [])

    def test_ambiguous_write_readback_can_prove_convergence(self):
        client = FakeClient(["a"], failure=True)
        result = ops.topic_action(client, "szl-drift", ["b"], True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(len(client.writes), 1)

    def test_failed_write_never_retries(self):
        client = FakeClient(["a"], failure=True, keep_write=False)
        result = ops.topic_action(client, "szl-drift", ["b"], True)
        self.assertEqual(result["status"], "UNKNOWN_AFTER_ATTEMPT")
        self.assertEqual(len(client.writes), 1)

    def test_topic_limit_never_discards_existing(self):
        client = FakeClient([f"topic-{i}" for i in range(20)])
        result = ops.topic_action(client, "szl-drift", ["new"], True)
        self.assertEqual(result["reason"], "TOPIC_LIMIT_PRESERVE_EXISTING")
        self.assertEqual(client.writes, [])

    def test_missing_permission_blocks(self):
        client = FakeClient(["a"], admin=False)
        result = ops.topic_action(client, "szl-drift", ["b"], True)
        self.assertEqual(result["reason"], "TOPIC_ADMIN_PERMISSION_UNVERIFIED")
        self.assertEqual(client.writes, [])


class RequestContracts(unittest.TestCase):
    def test_error_object_is_not_inventory(self):
        client = ops.Client()
        with patch.object(client, "request", return_value={"message": "rate limited"}):
            with self.assertRaisesRegex(ops.GitHubError, "INVALID_LIST_RESPONSE"):
                client.pages("orgs/szl-holdings/repos")

    def test_pagination_is_bounded(self):
        client = ops.Client(max_pages=1)
        with patch.object(client, "request", return_value=[{"id": i} for i in range(100)]):
            with self.assertRaisesRegex(ops.GitHubError, "PAGINATION_LIMIT_REACHED"):
                client.pages("orgs/szl-holdings/repos")

    def test_repeated_pages_rejected(self):
        client = ops.Client()
        with patch.object(client, "request", return_value=[{"id": i} for i in range(100)]):
            with self.assertRaisesRegex(ops.GitHubError, "PAGINATION_REPEATED_PAGE"):
                client.pages("orgs/szl-holdings/repos")

    def test_paths_cannot_exfiltrate_credentials(self):
        client = ops.Client()
        with self.assertRaisesRegex(ops.GitHubError, "INVALID_API_PATH"):
            client.request("https://example.com")

    def test_mutations_have_fixed_allowlist(self):
        client = ops.Client()
        with self.assertRaisesRegex(ops.GitHubError, "MUTATION_OUTSIDE_ALLOWLIST"):
            client.request("repos/szl-holdings/a11oy", "PUT", {"archived": True})


class ReadRetryContracts(unittest.TestCase):
    def client(self, use_gh=True):
        client = ops.Client()
        client.gh = "gh-test" if use_gh else None
        client.token = None
        return client

    @staticmethod
    def response(body=b'{"names": ["existing"]}', status=200, retry_after=None):
        headers = f"HTTP/2.0 {status} Test\r\nContent-Type: application/json\r\n"
        if retry_after is not None:
            headers += f"Retry-After: {retry_after}\r\n"
        return subprocess.CompletedProcess([], 0 if status == 200 else 1,
            headers.encode() + b"\r\n" + body, f"HTTP {status}".encode() if status != 200 else b"")

    def test_read_timeout_then_success_has_bounded_safe_evidence(self):
        client = self.client()
        with patch.object(ops.subprocess, "run", side_effect=[subprocess.TimeoutExpired("gh", 30), self.response()]) as run, \
                patch.object(ops.time, "sleep") as sleep:
            self.assertEqual(client.request("user"), {"names": ["existing"]})
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(1.0)
        self.assertEqual(client.diagnostics["read_retries"], 1)
        self.assertEqual(client.diagnostics["retry_events"][0]["code"], "TRANSPORT_TIMEOUT")

    def test_read_timeout_exhaustion_stays_failed(self):
        client = self.client()
        with patch.object(ops.subprocess, "run", side_effect=subprocess.TimeoutExpired("gh", 30)) as run, \
                patch.object(ops.time, "sleep") as sleep:
            with self.assertRaises(ops.GitHubError) as error:
                client.request("user")
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(ops.error_record(error.exception), {
            "code": "TRANSPORT_TIMEOUT", "http_status": None, "attempts": 3,
            "retry_stopped": "ATTEMPTS_EXHAUSTED"})

    def test_network_stderr_classification_does_not_leak_details(self):
        client = self.client()
        failed = subprocess.CompletedProcess([], 1, b"private_provider_body",
            b"read tcp: connection reset by peer fixture_secret_value")
        with patch.object(ops.subprocess, "run", side_effect=[failed, self.response()]), \
                patch.object(ops.time, "sleep"):
            client.request("user")
        encoded = json.dumps(client.diagnostics)
        self.assertIn("TRANSPORT_NETWORK_ERROR", encoded)
        self.assertNotIn("fixture_secret_value", encoded)
        self.assertNotIn("private_provider_body", encoded)

    def test_retryable_http_statuses_recover(self):
        for status in (429, 502, 503, 504):
            with self.subTest(status=status):
                client = self.client()
                with patch.object(ops.subprocess, "run", side_effect=[self.response(status=status), self.response()]) as run, \
                        patch.object(ops.time, "sleep"):
                    client.request("user")
                self.assertEqual(run.call_count, 2)

    def test_interrupted_success_headers_or_body_retry_only_get(self):
        for stdout in (b'HTTP/2.0 200 OK\r\nContent-Type:',
                       b'HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n{"names":'):
            failure = subprocess.CompletedProcess([], 1, stdout, b'read tcp: connection reset by peer')
            with self.subTest(partial_bytes=len(stdout)):
                client = self.client()
                with patch.object(ops.subprocess, "run", side_effect=[failure, self.response()]) as run, \
                        patch.object(ops.time, "sleep"):
                    self.assertEqual(client.request("user"), {"names": ["existing"]})
                self.assertEqual(run.call_count, 2)
                self.assertEqual(client.diagnostics["retry_events"][0]["http_status"], 200)
                client = self.client()
                with patch.object(ops.subprocess, "run", return_value=failure) as run, \
                        patch.object(ops.time, "sleep") as sleep:
                    with self.assertRaises(ops.GitHubError):
                        client.request("repos/szl-holdings/szl-platform/issues", "POST", {"title": "fixture"})
                self.assertEqual(run.call_count, 1)
                sleep.assert_not_called()

    def test_retry_after_is_honored_within_bound(self):
        client = self.client()
        with patch.object(ops.subprocess, "run", side_effect=[self.response(status=429, retry_after="4"), self.response()]), \
                patch.object(ops.time, "sleep") as sleep:
            client.request("user")
        sleep.assert_called_once_with(4.0)

    def test_retry_after_above_bound_stops_without_early_retry(self):
        client = self.client()
        with patch.object(ops.subprocess, "run", return_value=self.response(status=429, retry_after="60")) as run, \
                patch.object(ops.time, "sleep") as sleep:
            with self.assertRaises(ops.GitHubError) as error:
                client.request("user")
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()
        self.assertEqual(error.exception.retry_stopped, "RETRY_AFTER_EXCEEDS_BOUND")

    def test_permission_auth_and_not_found_are_not_retried(self):
        for status in (401, 403, 404):
            with self.subTest(status=status):
                client = self.client()
                with patch.object(ops.subprocess, "run", return_value=self.response(status=status, retry_after="1")) as run, \
                        patch.object(ops.time, "sleep") as sleep:
                    with self.assertRaises(ops.GitHubError):
                        client.request("user")
                self.assertEqual(run.call_count, 1)
                sleep.assert_not_called()

    def test_unknown_cli_failure_is_not_assumed_transient(self):
        client = self.client()
        with patch.object(ops.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"unsupported option")) as run, \
                patch.object(ops.time, "sleep") as sleep:
            with self.assertRaisesRegex(ops.GitHubError, "GITHUB_REQUEST_FAILED"):
                client.request("user")
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    def test_post_and_put_never_retry_transient_failures(self):
        for method, path in (("POST", "repos/szl-holdings/szl-platform/issues"),
                             ("PUT", "repos/szl-holdings/szl-drift/topics")):
            for failure in (subprocess.TimeoutExpired("gh", 30), self.response(status=503)):
                with self.subTest(method=method, failure=type(failure).__name__):
                    client = self.client()
                    behavior = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                    with patch.object(ops.subprocess, "run", **behavior) as run, patch.object(ops.time, "sleep") as sleep:
                        with self.assertRaises(ops.GitHubError) as error:
                            client.request(path, method, {"names": ["existing"]})
                    self.assertEqual(run.call_count, 1)
                    self.assertEqual(error.exception.attempts, 1)
                    sleep.assert_not_called()
                    self.assertEqual(client.diagnostics["mutation_retries"], 0)

    def test_invalid_json_does_not_retry(self):
        client = self.client()
        with patch.object(ops.subprocess, "run", return_value=self.response(body=b"not json")) as run:
            with self.assertRaisesRegex(ops.GitHubError, "INVALID_JSON_RESPONSE"):
                client.request("user")
        self.assertEqual(run.call_count, 1)

    def test_http_fallback_retry_after_and_readback(self):
        client = self.client(use_gh=False)
        failure = urllib.error.HTTPError("https://api.github.com/user", 503, "Unavailable",
                                        {"Retry-After": "2"}, None)
        with patch.object(ops.urllib.request, "urlopen", side_effect=[failure, io.BytesIO(b'{"login":"fixture"}')]) as request, \
                patch.object(ops.time, "sleep") as sleep:
            self.assertEqual(client.request("user"), {"login": "fixture"})
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(2.0)

    def test_http_date_retry_after_is_parsed_and_bounded(self):
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=6)
        value = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        self.assertGreater(ops.retry_after_seconds(value), 4)
        self.assertLessEqual(ops.retry_after_seconds(value), 6)
        self.assertIsNone(ops.retry_after_seconds("fixture-private-header-value"))


class IssueContracts(unittest.TestCase):
    def test_explicit_mirror_card_is_classified(self):
        kind, evidence = ops.classify_hf_card("Canonical GitHub source: example\nThis model-type repo is the publish / card mirror.")
        self.assertEqual(kind, "software_mirror")
        self.assertTrue(evidence)

    def test_downloads_alone_are_not_classification(self):
        self.assertEqual(ops.classify_hf_card("downloads: 0"), (None, []))

    def test_missing_hf_evidence_remains_unverified(self):
        self.assertFalse(ops.valid_hf_evidence([], dt.datetime.now(dt.timezone.utc).isoformat()))

    def test_closed_issue_counts_as_existing(self):
        item = {"title": "old title", "body": "<!-- marker -->", "state": "closed"}
        self.assertIs(ops.issue_match([item], "<!-- marker -->", ["different"]), item)

    def test_alias_matches_without_marker(self):
        item = {"title": "OLD TITLE", "body": ""}
        self.assertIs(ops.issue_match([item], "<!-- marker -->", ["old title"]), item)

    def test_stale_router_claim_is_suppressed(self):
        result = ops.build_issue_plans({"archived": False, "description": "Receipt-bound inference gateway"}, None,
                                       dt.datetime.now(dt.timezone.utc).isoformat())
        self.assertEqual(result, [])

    def test_known_software_types_do_not_generate_zero_download_issue(self):
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        records = [{"id": "SZLHOLDINGS/" + name, "sha": "a" * 40, "observed_at": timestamp,
                    "classification": "software_mirror", "classification_evidence": "Not trained weights",
                    "downloads": 0} for name in ops.HF_TRIAGE]
        result = ops.build_issue_plans({"archived": False, "description": "gateway"}, records, timestamp)
        self.assertEqual(result, [])

    def test_stale_hf_evidence_does_not_create_issue(self):
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        records = [{"id": "SZLHOLDINGS/" + name, "sha": "a" * 40,
                    "observed_at": "2020-01-01T00:00:00+00:00"} for name in ops.HF_TRIAGE]
        self.assertFalse(ops.valid_hf_evidence(records, timestamp))

    def test_already_tracked_does_not_post(self):
        client = FakeClient()
        plan = {"repository": "szl-platform", "marker": "<!-- marker -->", "aliases": [],
                "title": "audit", "body": "<!-- marker -->"}
        found = {"title": "audit", "body": "<!-- marker -->", "state": "closed", "html_url": "https://github.com/example"}
        with patch.object(ops, "all_issues", return_value=[found]):
            result = ops.reconcile_issue(client, plan, True)
        self.assertEqual(result["status"], "ALREADY_TRACKED")
        self.assertEqual(client.writes, [])

    def test_issue_timeout_is_not_retried(self):
        client = unittest.mock.Mock()
        client.pages.return_value = []
        client.request.side_effect = [
            {"archived": False, "has_issues": True}, ops.GitHubError("TRANSPORT_TIMEOUT")]
        plan = {"repository": "szl-platform", "marker": "<!-- marker -->", "aliases": [],
                "title": "audit", "body": "<!-- marker -->"}
        with patch.object(ops, "all_issues", return_value=[]):
            result = ops.reconcile_issue(client, plan, True)
        self.assertEqual(result["status"], "UNKNOWN_AFTER_ATTEMPT")
        posts = [call for call in client.request.call_args_list if len(call.args) > 1 and call.args[1] == "POST"]
        self.assertEqual(len(posts), 1)

    def test_issue_creation_requires_exact_readback(self):
        client = unittest.mock.Mock()
        client.pages.return_value = [{"name": "estate-audit"}]
        plan = {"repository": "szl-platform", "marker": "<!-- marker -->", "aliases": [],
                "title": "audit", "body": "<!-- marker -->\nFresh facts", "labels": ["estate-audit", "missing"]}
        client.request.side_effect = [
            {"archived": False, "has_issues": True}, {"number": 42},
            {"number": 42, "body": plan["body"], "title": "audit", "html_url": "https://github.com/example/issues/42"}]
        with patch.object(ops, "all_issues", return_value=[]):
            result = ops.reconcile_issue(client, plan, True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["applied_labels"], ["estate-audit"])

    def test_not_trained_large_model_disclaimer_does_not_hide_software_kind(self):
        kind, evidence = ops.classify_hf_card("A Python package with a tiny model.\nNot trained weights at 1-2B.")
        self.assertEqual(kind, "software_mirror")
        self.assertTrue(evidence)


if __name__ == "__main__":
    unittest.main()
