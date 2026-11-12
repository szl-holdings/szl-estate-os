#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build cloudflare/snapshots/2026-11-06 from the coordinator's read-only captures.

Provenance script for the first baseline. It reads files written on 2026-11-06
by the coordinator's Cloudflare audit. Those files are not in this repository:
some of them also hold API-token metadata, the account audit log and personal
e-mail addresses. The script normalizes the reads with the same functions the
live drift check uses (cloudflare/cf_config.py), so a later live export is
directly comparable:

  cf_audit.json                  ~15:06Z  zone settings, DNS, ruleset details with action_parameters
  inspect_1610.json              ~16:11Z  current WAF/rate-limit/config rule lists, bot settings,
                                          Workers metadata, tunnel names and status
  monetization_rules_1650.json   ~16:26Z  Monetization Gateway rules
  monetization_changes_1655.json 16:27Z   the three rules the coordinator disabled (HTTP 200 each)
  szlholdings_zone.json          ~15:25Z  the pending szlholdings.com zone
  szlholdings_dns_after.json     ~15:31Z  szlholdings.com DNS after the approved onboarding

A value no capture recorded is written as {"$uncaptured": "<reason>"}. The drift
check reports it as a baseline gap and never as a match.

Usage (the coordinator's machine):
  python -I -B cloudflare/build_snapshot_20261106.py --source-dir /home/user/szl/_cf \
      --out cloudflare/snapshots/2026-11-06
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def _load_cf_config():
    spec = importlib.util.spec_from_file_location("cf_config", HERE / "cf_config.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cf = _load_cf_config()

SOURCES = {
    "cf_audit": "cf_audit.json",
    "inspect": "inspect_1610.json",
    "monetization_rules": "monetization_rules_1650.json",
    "monetization_changes": "monetization_changes_1655.json",
    "szlholdings_zone": "szlholdings_zone.json",
    "szlholdings_dns": "szlholdings_dns_after.json",
}
ZONES = ("a-11-oy.com", "a11oy.net", "szlholdings.com")
EXCLUDED = [
    "API tokens and token metadata (inspect_1610.json tokens)",
    "the account audit log and its actor e-mail addresses",
    "account name, members, billing and registrar contacts",
    "e-mail routing rules and destination addresses",
    "Worker secret_text values (the API never returns them) and plain_text binding values (stored as SHA-256)",
    "TXT values other than SPF/DMARC policy (stored as SHA-256 and length)",
    "DNS record ids and comments, ruleset ids, versions and timestamps",
    "D1, R2, AI Gateway, Access applications, notification policies, zone settings and certificates: not exported",
]
KNOWN_CHANGES_AFTER_CAPTURE = [
    "2026-11-06T15:08:20Z: the account audit log records a DNS record created in a-11-oy.com by another actor, "
    "after the 15:06Z DNS capture (CLOUDFLARE_REPORT CF-8: showcase.a-11-oy.com). It is not in this baseline, so "
    "the first live drift run is expected to report it as an added record.",
    "2026-11-06T15:31:28Z-15:35:49Z: rulesets_update events on a-11-oy.com. The WAF, rate-limit and configuration "
    "rule lists here come from the 16:11Z read, which postdates them; action_parameters come from the 15:06Z read "
    "and are only reused where description, expression and action are unchanged.",
    "2026-11-06T16:27:21Z-16:27:25Z: the coordinator disabled three Monetization Gateway rules "
    "(monetization_changes_1655.json); this baseline applies those changes to the 16:26Z rule read.",
]


def _mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _captured(source: str, files: dict[str, Path], note: str | None = None) -> dict[str, Any]:
    entry = {"source": f"_cf/{SOURCES[source]}", "file_written_at": _mtime(files[source])}
    if note:
        entry["note"] = note
    return entry


def _rules(
    current: list[dict[str, Any]],
    detailed: list[dict[str, Any]],
    *,
    reason: str,
    ratelimit_reason: str | None = None,
) -> list[dict[str, Any]]:
    """Merge the 16:11Z rule list (order, enabled) with 15:06Z details (action_parameters)."""
    merged = []
    for rule in current:
        match = [
            item
            for item in detailed
            if item.get("description") == rule["desc"] and item.get("expression") == rule["expr"]
        ]
        if len(match) > 1:
            raise SystemExit(f"ambiguous rule match for {rule['desc']!r}")
        raw: dict[str, Any] = {
            "description": rule["desc"],
            "expression": rule["expr"],
            "action": rule.get("action", match[0]["action"] if match else None),
            "enabled": rule.get("enabled", match[0].get("enabled") if match else None),
            "action_parameters": rule.get("action_parameters"),
        }
        if match and not raw["action_parameters"]:
            raw["action_parameters"] = match[0].get("action_parameters")
        if raw["action"] is None or raw["enabled"] is None:
            raise SystemExit(f"rule {rule['desc']!r} has no action or enabled flag in either capture")
        normalized = cf.normalize_rule(raw)
        if not match:
            normalized["action_parameters"] = cf.placeholder(reason)
        if ratelimit_reason:
            normalized["ratelimit"] = cf.placeholder(ratelimit_reason)
        merged.append(normalized)
    return merged


def build(source_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    files = {name: source_dir / filename for name, filename in SOURCES.items()}
    data = {name: json.loads(path.read_text(encoding="utf-8")) for name, path in files.items()}
    audit, inspect = data["cf_audit"], data["inspect"]
    scopes: dict[str, dict[str, Any]] = {}

    disabled = {
        (change["zone"], change["rule"])
        for change in data["monetization_changes"]
        if change.get("patch_status") == 200 and change.get("after_enabled") is False
    }
    if len(disabled) != 3:
        raise SystemExit(f"expected 3 applied monetization changes, found {len(disabled)}")

    for zone in ZONES:
        sections: dict[str, Any] = {}
        if zone == "szlholdings.com":
            sections["zone"] = {
                "captured": _captured("szlholdings_zone", files),
                "data": cf.normalize_zone(data["szlholdings_zone"]["zone"]),
            }
            sections["dns"] = {
                "captured": _captured("szlholdings_dns", files),
                "data": sorted(
                    (cf.normalize_dns_record(record) for record in data["szlholdings_dns"]), key=cf.dns_sort_key
                ),
            }
        else:
            zone_audit = audit["zones"][zone]
            sections["zone"] = {
                "captured": _captured("cf_audit", files),
                "data": cf.normalize_zone({"name": zone, **zone_audit}),
            }
            records = []
            for record in zone_audit["dns"]:
                normalized = cf.normalize_dns_record(record)
                if record["type"] == "MX" and "priority" not in record:
                    normalized["priority"] = cf.placeholder("cf_audit.json did not record MX priority")
                records.append(normalized)
            sections["dns"] = {"captured": _captured("cf_audit", files), "data": sorted(records, key=cf.dns_sort_key)}

        zone_inspect = inspect["zones"][zone]
        details = {
            ruleset["phase"]: ruleset.get("rules", [])
            for ruleset in (audit["zones"].get(zone, {}).get("ruleset_details") or [])
        }
        rules_note = "rule list, order and enabled flags from the 16:11Z read; action_parameters from cf_audit.json"
        sections["waf_custom"] = {
            "captured": _captured("inspect", files, rules_note),
            "data": _rules(
                zone_inspect["custom_rules"],
                details.get("http_request_firewall_custom", []),
                reason="rule added after the 15:06Z read; inspect_1610.json did not record action_parameters",
            ),
        }
        sections["rate_limit"] = {
            "captured": _captured("inspect", files, rules_note),
            "data": _rules(
                zone_inspect["ratelimit_rules"],
                details.get("http_ratelimit", []),
                reason="not recorded",
                ratelimit_reason="neither capture recorded the rate-limit characteristics, period or threshold",
            ),
        }
        sections["config_rules"] = {
            "captured": _captured("inspect", files, rules_note),
            "data": _rules(
                zone_inspect["config_rules"],
                details.get("http_config_settings", []),
                reason="rule added after the 15:06Z read",
            ),
        }
        sections["bot_management"] = {
            "captured": _captured("inspect", files),
            "data": cf.normalize_bot_management(zone_inspect["bot_management"]),
        }

        payload = data["monetization_rules"][zone]
        if payload.get("status") == 200:
            rules = []
            for rule in payload["result"]["rules"]:
                rule = dict(rule)
                if (zone, rule["id"]) in disabled:
                    if rule.get("enabled") is not True:
                        raise SystemExit(f"change log disables {rule['id']}, which was not enabled")
                    rule["enabled"] = False
                rules.append(cf.normalize_monetization_rule(rule))
            monetization = sorted(rules, key=lambda item: item["id"])
            note = "16:26Z rule read with the three 16:27Z disables of monetization_changes_1655.json applied"
        elif payload.get("status") == 404 and any(error.get("code") == 10005 for error in payload.get("errors", [])):
            monetization = []
            note = "HTTP 404, code 10005 'payment rule not found': the zone has no rules"
        else:
            raise SystemExit(f"unexpected monetization read for {zone}: {payload.get('status')}")
        sections["monetization_rules"] = {"captured": _captured("monetization_rules", files, note), "data": monetization}
        scopes[f"zone:{zone}"] = sections

    workers = []
    for worker in inspect["workers"]:
        normalized = cf.normalize_worker(
            worker["name"],
            {"bindings": worker.get("bindings"), "compatibility_date": worker.get("compat")},
            {"created_on": worker.get("created_on"), "modified_on": worker.get("modified_on")},
        )
        for binding in normalized["bindings"]:
            if binding["type"] == "plain_text" and "value_sha256" not in binding:
                binding["value_sha256"] = cf.placeholder("inspect_1610.json did not record this plain_text value")
        workers.append(normalized)
    scopes["account"] = {
        "workers": {
            "captured": _captured("inspect", files),
            "data": sorted(workers, key=lambda item: item["name"]),
        },
        "tunnels": {
            "captured": _captured("inspect", files),
            "data": sorted((cf.normalize_tunnel(tunnel) for tunnel in inspect["tunnels"]), key=lambda item: item["name"]),
        },
    }
    manifest_extra = {
        "snapshot": "2026-11-06",
        "generated_by": "cloudflare/build_snapshot_20261106.py",
        "sources": [
            {
                "file": f"_cf/{SOURCES[name]}",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "file_written_at": _mtime(path),
            }
            for name, path in files.items()
        ],
        "placeholder_marker": cf.PLACEHOLDER,
        "volatile_marker": cf.STATE,
        "excluded": EXCLUDED,
        "known_changes_after_capture": KNOWN_CHANGES_AFTER_CAPTURE,
    }
    return scopes, manifest_extra


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    scopes, manifest_extra = build(args.source_dir)
    findings = [finding for scope in scopes.values() for finding in cf.secret_findings(scope)]
    if findings:
        print("refusing to write a snapshot with secret patterns:\n" + "\n".join(findings), file=sys.stderr)
        return 1
    manifest = cf.write_snapshot(args.out, scopes, manifest_extra)
    cf.load_snapshot(args.out)
    print(f"wrote {args.out}: {len(manifest['files'])} files")
    for relative, entry in manifest["files"].items():
        print(f"  {relative}  sha256 {entry['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
