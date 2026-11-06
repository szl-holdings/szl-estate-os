# SPDX-License-Identifier: Apache-2.0
"""Offline contracts for cloudflare/cf_config.py and the committed snapshot.

Run:  python -I -B cloudflare/test_cf_config.py -v

Every Cloudflare API response comes from a local http.server stub on
127.0.0.1 that records each request; no test touches the network and no real
token is used.
"""
from __future__ import annotations

import copy
import hashlib
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SNAPSHOT = HERE / "snapshots" / "2026-11-06"
DRIFT_WORKFLOW = ROOT / ".github" / "workflows" / "cloudflare-config-drift.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "cloudflare-config-ci.yml"
TOKEN = "TestOnlyToken_not-a-real-credential-0123456789"


def load_module():
    spec = importlib.util.spec_from_file_location("cf_config_under_test", HERE / "cf_config.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


cf = load_module()

ZONE_A = "example.test"
ZONE_B = "proof.test"
ACCOUNT = "0123456789abcdef0123456789abcdef"


def fake_account() -> dict:
    """A small API-shaped account with two zones."""
    def zone(name: str, zone_id: str) -> dict:
        return {
            "id": zone_id,
            "name": name,
            "status": "active",
            "type": "full",
            "paused": False,
            "plan": {"id": "x", "name": "Pro Website", "price": 20},
            "name_servers": ["simon.ns.cloudflare.com", "desiree.ns.cloudflare.com"],
            "account": {"id": ACCOUNT, "name": "owner@example.invalid's Account"},
            "permissions": ["#zone:read"],
        }

    def record(rtype: str, name: str, content: str, proxied: bool = False, **extra) -> dict:
        return {
            "id": hashlib.md5(f"{rtype}{name}{content}".encode()).hexdigest(),
            "zone_id": "ignored",
            "type": rtype,
            "name": name,
            "content": content,
            "proxied": proxied,
            "proxiable": True,
            "ttl": 1,
            "comment": "operator note",
            "meta": {"auto_added": False},
            "created_on": "2026-11-01T00:00:00Z",
            "modified_on": "2026-11-01T00:00:00Z",
            **extra,
        }

    skip = {
        "id": "r1",
        "version": "3",
        "ref": "r1",
        "last_updated": "2026-11-06T15:31:28Z",
        "description": "Skip bot challenge on API hosts",
        "expression": '(http.host in {"api.example.test"})',
        "action": "skip",
        "enabled": True,
        "action_parameters": {"phases": ["http_request_sbfm"], "products": ["bic"]},
        "logging": {"enabled": True},
    }
    block = {
        "id": "r2",
        "version": "1",
        "ref": "r2",
        "last_updated": "2026-11-06T15:35:49Z",
        "description": "Block internals",
        "expression": '(http.request.uri.path in {"/metrics"})',
        "action": "block",
        "enabled": True,
    }
    return {
        "zones": {ZONE_A: zone(ZONE_A, "a" * 32), ZONE_B: zone(ZONE_B, "b" * 32)},
        "dns": {
            "a" * 32: [
                record("CNAME", ZONE_A, "space.hf.space", proxied=True),
                record("MX", ZONE_A, "route1.mx.cloudflare.net", priority=10),
                record("TXT", ZONE_A, '"v=spf1 include:_spf.mx.cloudflare.net ~all"'),
                record("TXT", f"_dmarc.{ZONE_A}", "v=DMARC1; p=reject"),
                record("TXT", f"k1._domainkey.{ZONE_A}", '"v=DKIM1; k=rsa; p=MIIBIjANBgkq"'),
                record("TXT", ZONE_A, '"site-verification=abc123"'),
            ],
            "b" * 32: [record("A", ZONE_B, "185.199.108.153", proxied=True)],
        },
        "rulesets": {
            ("a" * 32, "http_request_firewall_custom"): [skip, block],
            ("a" * 32, "http_ratelimit"): [
                {
                    "id": "r3",
                    "description": "API soft rate limit",
                    "expression": 'starts_with(http.request.uri.path, "/api/")',
                    "action": "block",
                    "enabled": True,
                    "ratelimit": {"characteristics": ["ip.src"], "period": 60, "requests_per_period": 100},
                }
            ],
            ("b" * 32, "http_request_firewall_custom"): [dict(block, id="r4")],
        },
        "bot": {
            "a" * 32: {"enable_js": True, "sbfm_definitely_automated": "managed_challenge", "using_latest_model": True},
            "b" * 32: {"enable_js": True, "ai_bots_protection": "block", "using_latest_model": True},
        },
        "monetization": {
            "a" * 32: [
                {
                    "id": "f" * 32,
                    "description": "Completions (everyone, x402)",
                    "enabled": True,
                    "expression": '(http.host eq "inference.example.test")',
                    "price": "20000",
                    "address": "0x50E9B335ac233fcc5e87404367E7De253A63D460",
                    "scheme": "exact",
                },
                {
                    "id": "e" * 32,
                    "description": "Catch-all (verified bots)",
                    "enabled": False,
                    "expression": "(cf.client.bot)",
                    "price": "100000",
                    "address": "0x50E9B335ac233fcc5e87404367E7De253A63D460",
                    "scheme": "exact",
                },
            ],
            "b" * 32: "404",
        },
        "workers": [
            {"id": "store", "created_on": "2026-10-17T01:13:33Z", "modified_on": "2026-11-06T15:27:37Z", "etag": "x"},
            {"id": "relay", "created_on": "2026-08-31T03:02:40Z", "modified_on": "2026-10-10T13:46:22Z", "etag": "y"},
        ],
        "settings": {
            "store": {
                "compatibility_date": "2026-10-01",
                "bindings": [
                    {"type": "secret_text", "name": "STORE_SECRET"},
                    {"type": "d1", "name": "DB", "id": "27edfa50-be82-4fa1-b0c8-0c630c7db3ea"},
                    {"type": "plain_text", "name": "SOURCE_REVISION", "text": "d739c95b"},
                ],
            },
            "relay": {"compatibility_date": "2026-08-31", "bindings": []},
        },
        "tunnels": [
            {"id": "11111111-1111-1111-1111-111111111111", "name": "inference", "status": "healthy",
             "connections": [{"id": "c1"}, {"id": "c2"}], "created_at": "2026-11-05T18:40:39Z"},
            {"id": "22222222-2222-2222-2222-222222222222", "name": "laptop", "status": "down", "connections": []},
        ],
        "forbidden": set(),
    }


def envelope(result, status: int = 200, errors=None, result_info=None) -> tuple[int, dict]:
    body = {"success": status == 200, "errors": errors or [], "messages": [], "result": result}
    if result_info is not None:
        body["result_info"] = result_info
    return status, body


class _ApiHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        return None

    def _reply(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _route(self) -> tuple[int, dict]:
        fake = self.server.fake
        parts = urlsplit(self.path)
        query = {key: values[0] for key, values in parse_qs(parts.query).items()}
        path = parts.path
        if not path.startswith("/client/v4/"):
            return envelope(None, 404, [{"code": 7000, "message": "No route"}])
        path = path[len("/client/v4") :]
        if path in fake["forbidden"]:
            return envelope(None, 403, [{"code": 10000, "message": "Authentication error"}])
        if path == "/zones":
            zone = fake["zones"].get(query.get("name", ""))
            return envelope([zone] if zone else [])
        match = re.fullmatch(r"/zones/([0-9a-f]{32})/dns_records", path)
        if match:
            records = fake["dns"][match.group(1)]
            page, per_page = int(query.get("page", 1)), int(query.get("per_page", 100))
            chunk = records[(page - 1) * per_page : page * per_page]
            pages = max(1, -(-len(records) // per_page))
            return envelope(chunk, result_info={"page": page, "per_page": per_page, "count": len(chunk),
                                                "total_count": len(records), "total_pages": pages})
        match = re.fullmatch(r"/zones/([0-9a-f]{32})/rulesets/phases/([a-z_]+)/entrypoint", path)
        if match:
            rules = fake["rulesets"].get((match.group(1), match.group(2)))
            if rules is None:
                return envelope(None, 404, [{"code": 10003, "message": "could not find entrypoint ruleset"}])
            return envelope({"id": "rs", "phase": match.group(2), "rules": rules})
        match = re.fullmatch(r"/zones/([0-9a-f]{32})/bot_management", path)
        if match:
            return envelope(fake["bot"][match.group(1)])
        match = re.fullmatch(r"/zones/([0-9a-f]{32})/monetization/rules", path)
        if match:
            rules = fake["monetization"][match.group(1)]
            if rules == "404":
                return envelope(None, 404, [{"code": 10005, "message": "payment rule not found"}])
            if rules == "404-other":
                return envelope(None, 404, [{"code": 7003, "message": "Could not route"}])
            return envelope({"rules": rules})
        if path == f"/accounts/{ACCOUNT}/workers/scripts":
            return envelope(fake["workers"])
        match = re.fullmatch(rf"/accounts/{ACCOUNT}/workers/scripts/([a-z-]+)/settings", path)
        if match:
            return envelope(fake["settings"][match.group(1)])
        if path == f"/accounts/{ACCOUNT}/cfd_tunnel":
            return envelope(fake["tunnels"], result_info={"page": 1, "per_page": 100, "count": len(fake["tunnels"]),
                                                          "total_count": len(fake["tunnels"])})
        return envelope(None, 404, [{"code": 7000, "message": "No route for that URI"}])

    def _serve(self) -> None:
        self.server.requests.append(
            {"method": self.command, "path": self.path, "authorization": self.headers.get("Authorization")}
        )
        if self.command != "GET":
            self._reply(405, {"success": False, "errors": [{"code": 10405, "message": "method not allowed"}]})
            return
        status, body = self._route()
        self._reply(status, body)

    do_GET = _serve
    do_POST = _serve
    do_PUT = _serve
    do_PATCH = _serve
    do_DELETE = _serve


class _Api(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, fake: dict) -> None:
        super().__init__(("127.0.0.1", 0), _ApiHandler)
        self.fake = fake
        self.requests: list[dict] = []

    def __enter__(self) -> "_Api":
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=5)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/client/v4"


class _Cli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cfcfg-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        environment = mock.patch.dict(os.environ, {cf.TOKEN_ENV: TOKEN}, clear=False)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("GITHUB_STEP_SUMMARY", None)

    def cli(self, *argv: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cf.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def baseline(self, fake: dict) -> Path:
        target = self.tmp / "baseline" / "2026-11-07"
        with _Api(fake) as api:
            code, output = self.cli("export", "--out", str(target), "--zone", ZONE_A, "--zone", ZONE_B,
                                    "--api-base", api.base)
        self.assertEqual(code, 0, output)
        return target

    def drift(self, fake: dict, baseline: Path, *extra: str) -> tuple[int, dict, _Api, str]:
        report = self.tmp / "report.json"
        with _Api(fake) as api:
            code, output = self.cli("drift", "--snapshot", str(baseline), "--report", str(report),
                                    "--api-base", api.base, *extra)
        return code, json.loads(report.read_text(encoding="utf-8")), api, output

    @staticmethod
    def section(report: dict, scope: str, name: str) -> dict:
        return next(row for row in report["sections"] if row["scope"] == scope and row["section"] == name)


class CommittedSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, self.scopes = cf.load_snapshot(SNAPSHOT)

    def test_snapshot_verifies_and_is_the_newest_baseline(self) -> None:
        self.assertEqual(cf.latest_snapshot(), SNAPSHOT)
        self.assertEqual(self.manifest["schema"], cf.SNAPSHOT_SCHEMA)
        self.assertEqual(
            sorted(self.scopes), ["account", "zone:a-11-oy.com", "zone:a11oy.net", "zone:szlholdings.com"]
        )
        for scope, sections in self.scopes.items():
            expected = cf.ACCOUNT_SECTIONS if scope == "account" else cf.ZONE_SECTIONS
            self.assertEqual(sorted(sections), sorted(expected), scope)
        out = io.StringIO()
        with redirect_stdout(out):
            code = cf.main(["verify-snapshot", "--snapshot", str(SNAPSHOT)])
        self.assertEqual(code, 0)
        self.assertIn("OK: 4 files, 23 sections, no secret patterns", out.getvalue())

    def test_snapshot_counts_match_the_captures(self) -> None:
        apex, proof, company = (self.scopes[f"zone:{zone}"] for zone in ("a-11-oy.com", "a11oy.net", "szlholdings.com"))
        self.assertEqual([len(apex["dns"]), len(proof["dns"]), len(company["dns"])], [27, 13, 15])
        self.assertEqual([len(apex["waf_custom"]), len(proof["waf_custom"]), len(company["waf_custom"])], [7, 1, 0])
        self.assertEqual(len(apex["monetization_rules"]), 15)
        self.assertEqual(len(proof["monetization_rules"]), 2)
        self.assertEqual(company["monetization_rules"], [])
        enabled = sorted((rule["id"][:8], rule["price"]) for rule in apex["monetization_rules"] if rule["enabled"])
        self.assertEqual(
            enabled, [("41cee0f8", "20000"), ("6babfd10", "20000"), ("94dc6d81", "50000"), ("b8026fdb", "25000")]
        )
        self.assertEqual([rule for rule in proof["monetization_rules"] if rule["enabled"]], [])
        self.assertEqual(len(self.scopes["account"]["workers"]), 5)
        tunnels = self.scopes["account"]["tunnels"]
        self.assertEqual(len(tunnels), 9)
        status = sorted(tunnel["_state"]["status"] for tunnel in tunnels)
        self.assertEqual(status.count("down"), 3)
        self.assertEqual(status.count("inactive"), 1)
        self.assertEqual(company["zone"]["status"], "pending")
        block = [rule for rule in apex["waf_custom"] if rule["description"].startswith("Block vLLM internals")]
        self.assertEqual(len(block), 1)
        self.assertIn('"/metrics" "/docs" "/openapi.json" "/redoc"', block[0]["expression"])

    def test_every_uncaptured_value_is_marked(self) -> None:
        placeholders = [
            path
            for scope, sections in self.scopes.items()
            for path, value in cf._walk(sections, scope)
            if cf.is_placeholder(value)
        ]
        self.assertEqual(len(placeholders), 10, placeholders)
        self.assertEqual(sum(path.endswith(".priority") for path in placeholders), 6)
        self.assertEqual(sum(path.endswith(".action_parameters") for path in placeholders), 2)
        self.assertEqual(sum(path.endswith(".ratelimit") for path in placeholders), 1)
        self.assertEqual(sum(path.endswith(".value_sha256") for path in placeholders), 1)

    def test_snapshot_holds_no_secret_patterns_or_raw_verification_values(self) -> None:
        for path in SNAPSHOT.rglob("*.json"):
            text = path.read_text(encoding="utf-8")
            self.assertEqual(cf.secret_findings(json.loads(text)), [], path)
            self.assertNotIn("@", text, path)
            self.assertNotIn("replit-verify", text, path)
            self.assertNotIn("70e819a8611582076239b07f16f6c3", text, path)
            self.assertNotIn("d739c95b", text, path)


class SnapshotVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cfsnap-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.copy = self.tmp / "2026-11-06"
        shutil.copytree(SNAPSHOT, self.copy)

    def rewrite(self, mutate) -> None:
        """Mutate one zone file and re-bind the manifest, so only the secret scan can object."""
        target = self.copy / "zones" / "a11oy.net.json"
        document = json.loads(target.read_text(encoding="utf-8"))
        mutate(document["sections"])
        data = cf.canonical_bytes(document)
        target.write_bytes(data)
        manifest_path = self.copy / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["zones/a11oy.net.json"]["sha256"] = hashlib.sha256(data).hexdigest()
        manifest_path.write_bytes(cf.canonical_bytes(manifest))

    def assert_rejected(self, fragment: str) -> None:
        with self.assertRaises(cf.SnapshotError) as raised:
            cf.load_snapshot(self.copy)
        self.assertIn(fragment, str(raised.exception))

    def test_tampered_bytes_fail_the_digest(self) -> None:
        target = self.copy / "account.json"
        target.write_bytes(target.read_bytes().replace(b'"down"', b'"healthy"', 1))
        self.assert_rejected("does not match the manifest")

    def test_unbound_files_are_rejected(self) -> None:
        (self.copy / "zones" / "extra.json").write_text("{}", encoding="utf-8")
        self.assert_rejected("files not bound by the manifest: zones/extra.json")

    def test_secret_patterns_are_rejected(self) -> None:
        cases = {
            "e-mail address": lambda s: s["dns"]["data"][0].update(content="owner@example.invalid"),
            "must be digested": lambda s: s["dns"]["data"].append(
                {"type": "TXT", "name": "x.a11oy.net", "content": "verify=abc", "proxied": False, "ttl": 1}
            ),
            "forbidden key": lambda s: s["zone"]["data"].update(api_token="redacted"),
            "40-character token-like value": lambda s: s["zone"]["data"].update(
                plan="Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0f"
            ),
            "bearer credential": lambda s: s["zone"]["data"].update(plan="Bearer abcdefgh12345678"),
            "PEM block": lambda s: s["zone"]["data"].update(plan="-----BEGIN PRIVATE KEY-----"),
        }
        for fragment, mutate in cases.items():
            with self.subTest(fragment):
                shutil.rmtree(self.copy)
                shutil.copytree(SNAPSHOT, self.copy)
                self.rewrite(mutate)
                self.assert_rejected(fragment)

    def test_baseline_sections_cannot_carry_errors(self) -> None:
        def mutate(sections):
            sections["dns"]["error"] = "HTTP 403"
        self.rewrite(mutate)
        self.assert_rejected("a baseline section needs data and no error")


class NormalizerTests(unittest.TestCase):
    def test_dns_keeps_routing_meaning_and_digests_token_like_txt(self) -> None:
        fake = fake_account()
        records = {r["content"]: cf.normalize_dns_record(r) for r in fake["dns"]["a" * 32]}
        self.assertEqual(
            records["space.hf.space"],
            {"type": "CNAME", "name": ZONE_A, "content": "space.hf.space", "proxied": True, "ttl": 1},
        )
        self.assertEqual(records["route1.mx.cloudflare.net"]["priority"], 10)
        self.assertEqual(records['"v=spf1 include:_spf.mx.cloudflare.net ~all"']["content"],
                         '"v=spf1 include:_spf.mx.cloudflare.net ~all"')
        self.assertEqual(records["v=DMARC1; p=reject"]["content"], "v=DMARC1; p=reject")
        dkim = records['"v=DKIM1; k=rsa; p=MIIBIjANBgkq"']
        self.assertEqual(dkim["content_kind"], "dkim")
        self.assertNotIn("content", dkim)
        verification = records['"site-verification=abc123"']
        self.assertEqual(verification["content_sha256"], hashlib.sha256(b'"site-verification=abc123"').hexdigest())
        self.assertEqual(verification["content_length"], len('"site-verification=abc123"'))
        # The coordinator's capture format (a subset of the API record) normalizes identically.
        capture = {"type": "CNAME", "name": ZONE_A, "content": "space.hf.space", "proxied": True, "ttl": 1,
                   "comment": "note"}
        self.assertEqual(cf.normalize_dns_record(capture), records["space.hf.space"])

    def test_rules_drop_ids_versions_and_logging(self) -> None:
        rule = fake_account()["rulesets"][("a" * 32, "http_request_firewall_custom")][0]
        self.assertEqual(
            cf.normalize_rule(rule),
            {
                "description": "Skip bot challenge on API hosts",
                "expression": '(http.host in {"api.example.test"})',
                "action": "skip",
                "enabled": True,
                "action_parameters": {"phases": ["http_request_sbfm"], "products": ["bic"]},
            },
        )

    def test_workers_and_tunnels_split_config_from_state(self) -> None:
        fake = fake_account()
        worker = cf.normalize_worker("store", fake["settings"]["store"], fake["workers"][0])
        self.assertEqual(
            worker["bindings"],
            [
                {"name": "DB", "type": "d1"},
                {"name": "SOURCE_REVISION", "type": "plain_text", "value_sha256": hashlib.sha256(b"d739c95b").hexdigest()},
                {"name": "STORE_SECRET", "type": "secret_text"},
            ],
        )
        self.assertEqual(worker["_state"]["modified_on"], "2026-11-06T15:27:37Z")
        tunnel = cf.normalize_tunnel(fake["tunnels"][0])
        self.assertEqual(tunnel, {"id": "11111111-1111-1111-1111-111111111111", "name": "inference",
                                  "_state": {"status": "healthy", "connections": 2}})
        self.assertEqual(cf.normalize_tunnel({"id": "x", "name": "y", "status": "down", "conns": 0})["_state"],
                         {"status": "down", "connections": 0})


class ExportAndDriftTests(_Cli):
    def test_unchanged_account_matches_and_the_token_never_leaks(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)
        cf.load_snapshot(baseline)
        code, report, api, output = self.drift(fake, baseline, "--export-dir", str(self.tmp / "live"))
        self.assertEqual(code, 0, output)
        self.assertEqual(report["verdict"], "MATCH")
        self.assertEqual(report["summary"], {"match": 16, "drift": 0, "baseline-gap": 0, "unverified": 0})
        self.assertTrue(api.requests)
        self.assertEqual({request["method"] for request in api.requests}, {"GET"})
        self.assertEqual({request["authorization"] for request in api.requests}, {f"Bearer {TOKEN}"})
        self.assertTrue(all(request["path"].startswith("/client/v4/") for request in api.requests))
        self.assertNotIn(TOKEN, output)
        for path in [self.tmp / "report.json", *self.tmp.rglob("*.json")]:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(TOKEN, text, path)
            self.assertNotIn("owner@example.invalid", text, path)
        dns = self.section(report, f"zone:{ZONE_A}", "dns")
        self.assertEqual(dns["status"], "match")
        self.assertEqual(self.section(report, f"zone:{ZONE_B}", "monetization_rules")["status"], "match")
        self.assertEqual(self.section(report, f"zone:{ZONE_B}", "rate_limit")["status"], "match")
        live = json.loads((self.tmp / "live" / "zones" / f"{ZONE_A}.json").read_text(encoding="utf-8"))
        self.assertEqual(len(live["sections"]["dns"]["data"]), 6)

    def test_configuration_changes_are_drift(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)

        def add_dns(f):
            f["dns"]["a" * 32].append(dict(f["dns"]["a" * 32][0], content="showcase.github.io", name=f"showcase.{ZONE_A}"))

        def enable_catch_all(f):
            f["monetization"]["a" * 32][1]["enabled"] = True

        def add_method_list(f):
            f["monetization"]["a" * 32][0]["methods"] = ["GET", "POST"]

        def reorder_waf(f):
            rules = f["rulesets"][("a" * 32, "http_request_firewall_custom")]
            rules.reverse()

        def widen_skip(f):
            f["rulesets"][("a" * 32, "http_request_firewall_custom")][0]["action_parameters"]["phases"].append(
                "http_ratelimit"
            )

        def change_binding(f):
            f["settings"]["store"]["bindings"][2]["text"] = "40-character-revision-0000000000000000000"

        def delete_tunnel(f):
            f["tunnels"].pop()

        def bot_setting(f):
            f["bot"]["b" * 32]["ai_bots_protection"] = "disabled"

        cases = {
            "dns": (add_dns, f"zone:{ZONE_A}", "added"),
            "monetization enabled": (enable_catch_all, f"zone:{ZONE_A}", "changed"),
            "monetization new field": (add_method_list, f"zone:{ZONE_A}", "added"),
            "waf order": (reorder_waf, f"zone:{ZONE_A}", "reordered"),
            "waf skip phases": (widen_skip, f"zone:{ZONE_A}", "removed"),
            "worker binding": (change_binding, "account", "changed"),
            "tunnel removed": (delete_tunnel, "account", "removed"),
            "bot management": (bot_setting, f"zone:{ZONE_B}", "changed"),
        }
        sections = {
            "dns": "dns", "monetization enabled": "monetization_rules", "monetization new field": "monetization_rules",
            "waf order": "waf_custom", "waf skip phases": "waf_custom", "worker binding": "workers",
            "tunnel removed": "tunnels", "bot management": "bot_management",
        }
        for name, (mutate, scope, change) in cases.items():
            with self.subTest(name):
                live = copy.deepcopy(fake)
                mutate(live)
                code, report, _, output = self.drift(live, baseline)
                self.assertEqual(code, 1, output)
                self.assertEqual(report["verdict"], "DRIFT")
                row = self.section(report, scope, sections[name])
                self.assertEqual(row["status"], "drift")
                self.assertIn(change, {item["change"] for item in row["differences"]})
                drifted = [r for r in report["sections"] if r["status"] == "drift"]
                self.assertEqual(len(drifted), 1, [r["section"] for r in drifted])

    def test_operational_state_is_reported_but_is_not_drift(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)
        live = copy.deepcopy(fake)
        live["tunnels"][1]["status"] = "healthy"
        live["tunnels"][1]["connections"] = [{"id": "c9"}]
        live["workers"][0]["modified_on"] = "2026-11-07T09:00:00Z"
        live["bot"]["a" * 32]["using_latest_model"] = False
        code, report, _, output = self.drift(live, baseline)
        self.assertEqual(code, 0, output)
        self.assertEqual(report["verdict"], "MATCH")
        tunnels = self.section(report, "account", "tunnels")
        self.assertEqual(tunnels["state_changes"][0]["live"], {"status": "healthy", "connections": 1})
        self.assertEqual(len(self.section(report, "account", "workers")["state_changes"]), 1)
        self.assertEqual(len(self.section(report, f"zone:{ZONE_A}", "bot_management")["state_changes"]), 1)

    def test_unreadable_sections_are_unverified_never_matched(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)
        live = copy.deepcopy(fake)
        live["forbidden"].add(f"/zones/{'a' * 32}/bot_management")
        code, report, _, output = self.drift(live, baseline)
        self.assertEqual(code, 3, output)
        self.assertEqual(report["verdict"], "INCOMPLETE")
        row = self.section(report, f"zone:{ZONE_A}", "bot_management")
        self.assertEqual(row["status"], "unverified")
        self.assertIn("HTTP 403 code 10000: Authentication error", row["error"])
        live["dns"]["b" * 32].append(dict(live["dns"]["b" * 32][0], content="185.199.109.153"))
        code, report, _, _ = self.drift(live, baseline)
        self.assertEqual((code, report["verdict"]), (1, "DRIFT"))

    def test_uncaptured_baseline_values_are_gaps_with_the_live_value(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)
        target = baseline / "zones" / f"{ZONE_A}.json"
        document = json.loads(target.read_text(encoding="utf-8"))
        for record in document["sections"]["dns"]["data"]:
            if record["type"] == "MX":
                record["priority"] = cf.placeholder("capture did not record MX priority")
        manifest = json.loads((baseline / "manifest.json").read_text(encoding="utf-8"))
        scopes = {}
        for relative, entry in manifest["files"].items():
            body = json.loads((baseline / relative).read_text(encoding="utf-8"))
            scopes[entry["scope"]] = document["sections"] if entry["scope"] == f"zone:{ZONE_A}" else body["sections"]
        extra = {key: value for key, value in manifest.items() if key not in ("schema", "files")}
        cf.write_snapshot(baseline, scopes, extra)
        code, report, _, output = self.drift(fake, baseline)
        self.assertEqual(code, 3, output)
        row = self.section(report, f"zone:{ZONE_A}", "dns")
        self.assertEqual(row["status"], "baseline-gap")
        self.assertEqual(row["gaps"][0]["live"], 10)

    def test_missing_entry_points_and_payment_rules_are_empty_not_errors(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)
        document = json.loads((baseline / "zones" / f"{ZONE_B}.json").read_text(encoding="utf-8"))
        self.assertEqual(document["sections"]["rate_limit"]["data"], [])
        self.assertEqual(document["sections"]["monetization_rules"]["data"], [])
        live = copy.deepcopy(fake)
        live["monetization"]["b" * 32] = "404-other"
        _, report, _, _ = self.drift(live, baseline)
        self.assertEqual(self.section(report, f"zone:{ZONE_B}", "monetization_rules")["status"], "unverified")

    def test_pagination_reads_every_dns_page(self) -> None:
        fake = fake_account()
        fake["dns"]["b" * 32] = [
            dict(fake["dns"]["b" * 32][0], name=f"h{index}.{ZONE_B}", content=f"192.0.2.{index % 250}")
            for index in range(250)
        ]
        baseline = self.baseline(fake)
        document = json.loads((baseline / "zones" / f"{ZONE_B}.json").read_text(encoding="utf-8"))
        self.assertEqual(len(document["sections"]["dns"]["data"]), 250)

    def test_invisible_zone_leaves_its_sections_unverified(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)
        live = copy.deepcopy(fake)
        del live["zones"][ZONE_B]
        code, report, _, _ = self.drift(live, baseline)
        self.assertEqual(code, 3)
        for name in cf.ZONE_SECTIONS:
            row = self.section(report, f"zone:{ZONE_B}", name)
            self.assertEqual(row["status"], "unverified")
            self.assertIn("zone lookup failed", row["error"])
        self.assertEqual(self.section(report, "account", "workers")["status"], "match")

    def test_step_summary_names_the_verdict(self) -> None:
        fake = fake_account()
        baseline = self.baseline(fake)
        summary = self.tmp / "summary.md"
        os.environ["GITHUB_STEP_SUMMARY"] = str(summary)
        live = copy.deepcopy(fake)
        live["monetization"]["a" * 32][1]["enabled"] = True
        code, _, _, _ = self.drift(live, baseline)
        self.assertEqual(code, 1)
        text = summary.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("## Cloudflare config drift: DRIFT\n"), text[:80])
        self.assertIn("| zone:example.test | monetization_rules | drift |", text)

    def test_token_and_api_base_are_validated(self) -> None:
        os.environ.pop(cf.TOKEN_ENV)
        code, output = self.cli("drift", "--snapshot", str(SNAPSHOT), "--report", str(self.tmp / "r.json"))
        self.assertEqual(code, 2)
        self.assertIn("CLOUDFLARE_READ_TOKEN is not set", output)
        os.environ[cf.TOKEN_ENV] = TOKEN
        for base in (
            "http://api.cloudflare.com/client/v4",
            "https://evil.example/client/v4",
            "http://10.0.0.5:8080/client/v4",
            "https://api.cloudflare.com/client/v5",
            "https://user:pass@api.cloudflare.com/client/v4",
        ):
            with self.subTest(base):
                code, output = self.cli("drift", "--snapshot", str(SNAPSHOT), "--report", str(self.tmp / "r.json"),
                                        "--api-base", base)
                self.assertEqual(code, 2, output)
        self.assertEqual(cf.parse_api_base(cf.API_BASE).host, "api.cloudflare.com")

    def test_client_refuses_unexpected_paths_and_queries(self) -> None:
        client = cf.ReadOnlyClient(TOKEN, base="http://127.0.0.1:9/client/v4")
        for path, query in (("/user/tokens/verify", None), ("/zones/../accounts", None), ("/zones", {"order": "x"})):
            with self.subTest(path=path, query=query), self.assertRaises(cf.ApiError):
                client.get(path, query)
        self.assertEqual(client.requests, 0)
        self.assertFalse(any(hasattr(client, name) for name in ("post", "put", "patch", "delete")))


class WorkflowContractTests(unittest.TestCase):
    def test_drift_workflow_skips_visibly_without_the_read_token(self) -> None:
        source = DRIFT_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('on:\n  schedule:\n    - cron: "', source)
        self.assertIn("\n  workflow_dispatch:\n", source)
        self.assertNotIn("pull_request", source)
        self.assertIn("\npermissions:\n  contents: read\n\n", source)
        self.assertNotRegex(source, r":\s*write\b")
        self.assertNotIn("continue-on-error", source)
        self.assertNotIn("|| true", source)
        references = re.findall(r"secrets\.[A-Za-z_]+", source)
        self.assertEqual(references, ["secrets.CLOUDFLARE_READ_TOKEN", "secrets.CLOUDFLARE_READ_TOKEN"])
        self.assertIn("TOKEN_PRESENT: ${{ secrets.CLOUDFLARE_READ_TOKEN != '' }}", source)
        self.assertIn("CLOUDFLARE_READ_TOKEN: ${{ secrets.CLOUDFLARE_READ_TOKEN }}", source)
        self.assertIn("::notice title=Cloudflare drift check skipped::", source)
        self.assertIn("if: needs.preflight.outputs.ready == 'true'", source)
        self.assertIn("github.ref == 'refs/heads/main'", source)
        live_job = source.split("\n  drift:\n", 1)[1]
        self.assertIn("egress-policy: block", live_job)
        self.assertIn("api.cloudflare.com:443", live_job)
        self.assertIn("python -I -B cloudflare/cf_config.py drift", live_job)
        for reference in re.findall(r"(?m)^\s+uses:\s*(\S+)", source):
            self.assertRegex(reference, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_ci_workflow_runs_offline_contracts_without_secrets(self) -> None:
        source = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  pull_request:\n", source)
        self.assertNotIn("secrets.", source)
        self.assertIn("\npermissions:\n  contents: read\n\n", source)
        self.assertIn("python -I -B cloudflare/test_cf_config.py -v", source)
        self.assertIn("python -I -B cloudflare/cf_config.py verify-snapshot", source)
        for reference in re.findall(r"(?m)^\s+uses:\s*(\S+)", source):
            self.assertRegex(reference, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
