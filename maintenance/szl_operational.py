#!/usr/bin/env python3
"""Run SZL's bounded GitHub, Hugging Face, and Cloudflare maintenance."""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROVIDERS = {"github": "github_ops", "huggingface": "hf_ops", "cloudflare": "cloudflare_ops"}
FAILURES = {"BLOCKED", "UNAVAILABLE", "FAILED", "ERROR", "READBACK_FAILED",
            "UNKNOWN_AFTER_ATTEMPT", "DRIFT", "DENIED", "PARTIAL"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


@contextmanager
def apply_lock(path):
    """Prevent two instances of this build from applying simultaneously.

    This is a local lock, not a claim of organization-wide writer ownership.
    A lock left after an interrupted process must be inspected before removal.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"pid": os.getpid(), "started_at": utc_now()}, stream)
        yield
    finally:
        path.unlink(missing_ok=True)


def has_failure(result, require_complete=False):
    if isinstance(result, dict):
        status = str(result.get("status", "")).upper()
        if result.get("blockers") or status in FAILURES or status.startswith("BLOCKED"):
            return True
        if require_complete and status in {"PLANNED", "PENDING", "UNKNOWN", "REPAIR_REQUIRED"}:
            return True
        if result.get("complete") is False:
            return True
        return any(has_failure(value, require_complete) for value in result.values())
    if isinstance(result, list):
        return any(has_failure(value, require_complete) for value in result)
    return False


def markdown_report(report):
    lines = ["# SZL maintenance run", "", f"Observed: {report['started_at']}", "",
             f"Mode: **{report['mode']}**. Status: **{report['status']}**.", "",
             "This report covers the supplied maintenance operations. It does not certify model training, application deployment, or production readiness.", "",
             "| Provider | Status | Action results |", "|---|---|---|"]
    for name, result in report["providers"].items():
        counts = Counter(a.get("status", "UNKNOWN") for a in result.get("actions", []))
        detail = ", ".join(f"{key}: {value}" for key, value in sorted(counts.items())) or "See JSON evidence"
        state = "NEEDS_ATTENTION" if has_failure(result, report["mode"] == "apply") else "VERIFIED" if report["mode"] == "apply" else "AUDITED"
        lines.append(f"| {name} | {state} | {detail} |")
    for name, result in report["providers"].items():
        if result.get("blockers"):
            lines += ["", f"## {name}: remaining work", ""]
            for blocker in result["blockers"]:
                if isinstance(blocker, dict):
                    label = blocker.get("target") or blocker.get("operation") or blocker.get("zone") or blocker.get("host") or blocker.get("url") or ", ".join(blocker.get("zones", [])) or "provider"
                    reason = blocker.get("reason") or blocker.get("message") or blocker.get("status") or blocker.get("type") or "See JSON"
                    lines.append(f"- {label}: {reason}")
                else:
                    lines.append(f"- {blocker}")
    return "\n".join(lines) + "\n"


def execute(args):
    report = {"schema": "szl.estate-maintenance.v2", "started_at": utc_now(),
              "mode": "apply" if args.apply else "audit", "status": "RUNNING", "providers": {}}
    for provider in args.providers:
        print(f"[{provider}] {'Applying and verifying' if args.apply else 'Auditing'}", flush=True)
        try:
            module = importlib.import_module(f"szl_estate.{PROVIDERS[provider]}")
            kwargs = {"apply": args.apply}
            if provider == "huggingface":
                kwargs["policy_path"] = args.hf_policy
            result = module.run(**kwargs)
            if not isinstance(result, dict):
                raise TypeError("Provider result must be an object")
        except Exception as exc:
            result = {"provider": provider, "status": "UNAVAILABLE", "actions": [],
                      "blockers": [{"reason": "Provider execution failed; no completion claim", "type": type(exc).__name__}]}
        report["providers"][provider] = result
        atomic_json(args.output / f"{provider}-result.json", result)
        atomic_json(args.output / "estate-state.json", report)
    report["finished_at"] = utc_now()
    report["status"] = "PARTIAL" if has_failure(report["providers"], args.apply) else "VERIFIED" if args.apply else "AUDITED"
    atomic_json(args.output / "estate-state.json", report)
    (args.output / "estate-report.md").write_text(markdown_report(report), encoding="utf-8")
    print(f"[{report['status']}] {args.output / 'estate-report.md'}")
    return 2 if report["status"] == "PARTIAL" else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Execute reviewed operations and verify provider readback; default is read-only")
    parser.add_argument("--providers", nargs="+", choices=tuple(PROVIDERS), default=list(PROVIDERS))
    parser.add_argument("--hf-policy", type=Path, default=ROOT / "hf-policy.json")
    parser.add_argument("--output", type=Path, default=ROOT / "runs" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    if len(set(args.providers)) != len(args.providers):
        parser.error("Each provider can be selected once")
    try:
        if args.apply:
            with apply_lock(ROOT / ".szl-apply.lock"):
                return execute(args)
        return execute(args)
    except FileExistsError:
        print("BLOCKED: another apply run owns the local lock. Inspect its process before retrying.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. Inspect checkpoint results before retrying writes.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
