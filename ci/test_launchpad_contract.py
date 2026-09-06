#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression contract for the source-bound command-center Launchpad."""
from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "payloads" / "command-center" / "app" / "launchpad.html"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "publish-command-center-launchpad.yml"
LOCK_PATH = ROOT / "requirements" / "launchpad-publisher.lock"

EXPECTED_DEPENDENCIES = {
    "anyio": "4.15.1",
    "certifi": "2026.7.22",
    "click": "8.5.0",
    "filelock": "3.32.5",
    "fsspec": "2026.7.0",
    "h11": "0.16.0",
    "hf-xet": "1.6.0",
    "httpcore": "1.0.9",
    "httpx": "0.28.1",
    "huggingface-hub": "1.23.0",
    "idna": "3.19",
    "packaging": "26.3",
    "pyyaml": "6.0.3",
    "tqdm": "4.70.0",
    "typing-extensions": "4.16.0",
}

ACTION_PINS = {
    "step-security/harden-runner": "bf7454d06d71f1098171f2acdf0cd4708d7b5920",
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
}


class _LaunchpadParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.ids: set[str] = set()
        self.has_main = False
        self.has_nav_label = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(str(attributes["id"]))
        if tag == "a" and attributes.get("href"):
            self.hrefs.append(str(attributes["href"]))
        if tag == "main":
            self.has_main = True
        if tag == "nav" and attributes.get("aria-label"):
            self.has_nav_label = True


class LaunchpadHtmlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = HTML_PATH.read_text(encoding="utf-8")
        cls.parser = _LaunchpadParser()
        cls.parser.feed(cls.text)

    def test_document_is_semantic_mobile_and_keyboard_accessible(self) -> None:
        self.assertIn('<html lang="en" data-szl-launchpad="v2">', self.text)
        self.assertIn('name="viewport"', self.text)
        self.assertIn('class="skip-link"', self.text)
        self.assertIn(':focus-visible', self.text)
        self.assertIn('min-height: 44px', self.text)
        self.assertIn('prefers-reduced-motion: reduce', self.text)
        self.assertIn('forced-colors: active', self.text)
        self.assertTrue(self.parser.has_main)
        self.assertTrue(self.parser.has_nav_label)
        self.assertIn("main", self.parser.ids)

    def test_navigation_is_explicitly_not_runtime_proof(self) -> None:
        for marker in (
            "A route appearing here is not a liveness, freshness, or production-readiness claim.",
            "Navigation does not certify runtime availability",
            "navigation is not runtime proof",
            "availability verified separately",
            "Lambda; remains Conjecture 1 and advisory only",
        ):
            self.assertIn(marker, self.text)
        self.assertNotIn("every link on this page resolves to a live surface", self.text)
        self.assertNotIn("Fleet health: 12 surfaces", self.text)
        self.assertNotIn("19 consoles lit", self.text)

    def test_front_door_has_no_external_font_or_unsafe_dom_dependency(self) -> None:
        self.assertNotIn("fonts.googleapis.com", self.text)
        self.assertNotIn("fonts.gstatic.com", self.text)
        self.assertNotIn(".innerHTML", self.text)
        self.assertNotIn("eval(", self.text)
        self.assertNotIn("document.write", self.text)
        self.assertIn('link.rel = "noopener noreferrer"', self.text)
        self.assertIn('link.textContent', self.text)

    def test_local_route_registry_is_fixed_and_constellation_is_bounded(self) -> None:
        local_hrefs = [href for href in self.parser.hrefs if not href.startswith("#")]
        self.assertTrue(local_hrefs)
        self.assertTrue(all(href.startswith("/") for href in local_hrefs))
        self.assertEqual(self.text.count('data-szl-constellation-count="19"'), 1)
        self.assertEqual(self.text.count('["'), 19)
        self.assertEqual(self.text.count("szlholdings-szl-${slug}.hf.space"), 1)


class LaunchpadPublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_workflow_is_manual_main_only_and_least_privilege(self) -> None:
        self.assertIn("workflow_dispatch: {}", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)
        self.assertIn("permissions:\n  contents: read", self.workflow)
        self.assertIn("github.repository == 'szl-holdings/szl-estate-os'", self.workflow)
        self.assertIn("github.ref == 'refs/heads/main'", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertNotIn("secrets: inherit", self.workflow)

    def test_every_third_party_action_is_immutably_pinned(self) -> None:
        observed = dict(
            re.findall(r"uses:\s+([^@\s]+)@([0-9a-f]{40})(?:\s|$)", self.workflow)
        )
        self.assertEqual(observed, ACTION_PINS)
        all_uses = re.findall(r"uses:\s+([^\s]+)", self.workflow)
        self.assertEqual(len(all_uses), len(ACTION_PINS))

    def test_secret_is_step_scoped_and_never_written_to_runner_state(self) -> None:
        self.assertIn("CANDIDATE_A: ${{ secrets.HF_TOKEN }}", self.workflow)
        self.assertIn("CANDIDATE_B: ${{ secrets.SZL_HF_TOKEN }}", self.workflow)
        self.assertIn("CANDIDATE_C: ${{ secrets.HF_WRITE_TOKEN }}", self.workflow)
        self.assertNotIn("GITHUB_ENV", self.workflow)
        self.assertNotIn("GITHUB_OUTPUT", self.workflow)
        self.assertNotIn("echo \"HF_TOKEN=", self.workflow)
        self.assertNotIn("print(token", self.workflow)
        self.assertIn('os.environ.pop(name, None)', self.workflow)

    def test_provider_mutation_is_atomic_parent_bound_and_exactly_verified(self) -> None:
        for marker in (
            "api.create_commit(",
            "parent_commit=parent_commit",
            "CommitOperationAdd(",
            "hf_hub_download(",
            "downloaded_html != payload",
            "downloaded_deployment != deployment_bytes",
            'current, "sha"',
            "body == payload",
            "COMMITTED_UNVERIFIED",
            "COMMITTED_AND_VERIFIED",
            "FAILED_CLOSED",
        ):
            self.assertIn(marker, self.workflow)
        self.assertEqual(self.workflow.count("CommitOperationAdd("), 2)
        self.assertNotIn(".upload_file(", self.workflow)
        self.assertIn("runtime did not expose the exact committed payload", self.workflow)
        self.assertIn("cross-origin redirect", self.workflow)

    def test_publication_emits_a_sanitized_long_lived_receipt(self) -> None:
        for marker in (
            "szl.launchpad-publication-receipt/v1",
            "szl.launchpad-deployment/v1",
            "payload_sha256",
            "provider_commit",
            "runtime_sha256",
            "retention-days: 90",
            "if-no-files-found: error",
        ):
            self.assertIn(marker, self.workflow)
        self.assertNotIn('"token":', self.workflow)
        self.assertNotIn('"credential":', self.workflow)

    def test_dependency_install_is_closed_over_the_exact_lock(self) -> None:
        self.assertIn("--only-binary=:all:", self.workflow)
        self.assertIn("--no-deps", self.workflow)
        self.assertIn("-r requirements/launchpad-publisher.lock", self.workflow)
        self.assertIn("python -m pip check", self.workflow)


class LaunchpadDependencyLockTests(unittest.TestCase):
    def test_dependency_lock_is_the_exact_closed_version_set(self) -> None:
        observed: dict[str, str] = {}
        for raw_line in LOCK_PATH.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+$")
            name, version = line.split("==", 1)
            normalized = name.casefold().replace("_", "-")
            self.assertNotIn(normalized, observed)
            observed[normalized] = version
        self.assertEqual(observed, EXPECTED_DEPENDENCIES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
