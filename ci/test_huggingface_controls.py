from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from SZL_ONE_OF_ONE_ESTATE_OS import (  # noqa: E402
    AuditConfig,
    collect_huggingface,
    normalize_hf_spaces,
)


class ExplicitHuggingFaceSpaceTests(unittest.TestCase):
    def test_identity_normalization_is_bounded_and_case_insensitive(self) -> None:
        self.assertEqual(
            ("betterwithage/anatomy",),
            normalize_hf_spaces(
                [" betterwithage/anatomy ", "BETTERWITHAGE/ANATOMY"]
            ),
        )
        for invalid in ("anatomy", "https://huggingface.co/anatomy", "a/b/c"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_hf_spaces([invalid])

    @patch("SZL_ONE_OF_ONE_ESTATE_OS.env_token", return_value=None)
    @patch("SZL_ONE_OF_ONE_ESTATE_OS.get_json")
    def test_cross_owner_space_is_observed_without_expanding_org_scope(
        self, get_json: Any, _env_token: Any
    ) -> None:
        response = SimpleNamespace(headers={})

        def fetch(url: str, **_: Any) -> tuple[Any, Any]:
            if "/api/models?" in url or "/api/datasets?" in url:
                return [], response
            if "/api/spaces?" in url:
                return [], response
            if url.endswith("/api/spaces/betterwithage/anatomy"):
                return (
                    {
                        "id": "betterwithage/anatomy",
                        "author": "betterwithage",
                        "private": False,
                        "sha": "a" * 40,
                        "sdk": "docker",
                        "runtime": {"stage": "RUNNING"},
                    },
                    response,
                )
            if "/api/collections?" in url:
                return [], response
            raise AssertionError(f"unexpected URL: {url}")

        get_json.side_effect = fetch
        assets, report = collect_huggingface(
            AuditConfig(
                hf_org="SZLHOLDINGS",
                hf_spaces=("betterwithage/anatomy",),
                deep=False,
            )
        )

        self.assertEqual("MEASURED", report.status)
        self.assertEqual(["betterwithage/anatomy"], report.metadata["explicit_spaces"])
        self.assertEqual(1, len(assets))
        self.assertEqual(
            "huggingface:space:betterwithage/anatomy", assets[0].asset_id
        )
        self.assertEqual("LIVE", assets[0].status_label)
        self.assertEqual("a" * 40, assets[0].metadata["revision"])


if __name__ == "__main__":
    unittest.main()
