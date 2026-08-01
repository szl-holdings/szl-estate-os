#!/usr/bin/env python3
"""Bounded concurrent load test for the read-only Estate OS HTTP API."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any


PATHS = (
    "/healthz",
    "/readyz",
    "/api/v1/status",
    "/api/v1/assets?limit=25",
    "/metrics",
)


def percentile(values: list[float], fraction: float) -> float:
    return values[min(len(values) - 1, int((len(values) - 1) * fraction))]


def wait_ready(base_url: str, process: subprocess.Popen[Any]) -> bool:
    for _ in range(100):
        if process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(base_url + "/readyz", timeout=1) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18787)
    parser.add_argument("--request-timeout", type=float, default=5.0)
    parser.add_argument("--max-error-rate", type=float, default=0.0)
    parser.add_argument("--max-p95-ms", type=float, default=2500.0)
    parser.add_argument("--min-rps", type=float, default=30.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.requests < 1 or args.concurrency < 1:
        parser.error("requests and concurrency must be positive")
    if not args.database.is_file():
        parser.error(f"database does not exist: {args.database}")

    root = Path(__file__).resolve().parents[1]
    program = root / "SZL_ONE_OF_ONE_ESTATE_OS.py"
    base_url = f"http://{args.host}:{args.port}"

    with tempfile.TemporaryDirectory(prefix="szl-estate-stress-") as temporary:
        stdout_path = Path(temporary) / "server.stdout"
        stderr_path = Path(temporary) / "server.stderr"
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(program),
                    "serve",
                    "--db",
                    str(args.database.resolve()),
                    "--host",
                    args.host,
                    "--port",
                    str(args.port),
                ],
                cwd=root,
                stdout=stdout,
                stderr=stderr,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                if not wait_ready(base_url, process):
                    raise RuntimeError("Estate OS server did not become ready")

                def request_once(index: int) -> tuple[int, float, int, str, str | None]:
                    path = PATHS[index % len(PATHS)]
                    started = time.perf_counter()
                    try:
                        with urllib.request.urlopen(
                            base_url + path, timeout=args.request_timeout
                        ) as response:
                            body = response.read()
                            return (
                                response.status,
                                (time.perf_counter() - started) * 1000,
                                len(body),
                                path,
                                None,
                            )
                    except Exception as exc:
                        return (
                            0,
                            (time.perf_counter() - started) * 1000,
                            0,
                            path,
                            f"{type(exc).__name__}: {exc}",
                        )

                started = time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=args.concurrency
                ) as pool:
                    results = list(pool.map(request_once, range(args.requests)))
                elapsed = time.perf_counter() - started
                latencies = sorted(item[1] for item in results)
                errors = [
                    {"path": item[3], "error": item[4]}
                    for item in results
                    if item[4]
                ]
                status_counts: dict[str, int] = {}
                for status, _, _, _, _ in results:
                    key = str(status)
                    status_counts[key] = status_counts.get(key, 0) + 1
                error_rate = len(errors) / args.requests
                p95_ms = percentile(latencies, 0.95)
                throughput = args.requests / elapsed

                with urllib.request.urlopen(
                    base_url + "/readyz", timeout=args.request_timeout
                ) as response:
                    post_ready = json.loads(response.read().decode("utf-8"))

                failures = []
                if error_rate > args.max_error_rate:
                    failures.append(
                        f"error_rate={error_rate:.6f} exceeds {args.max_error_rate:.6f}"
                    )
                if p95_ms > args.max_p95_ms:
                    failures.append(f"p95_ms={p95_ms:.2f} exceeds {args.max_p95_ms:.2f}")
                if throughput < args.min_rps:
                    failures.append(f"rps={throughput:.2f} below {args.min_rps:.2f}")
                if not post_ready.get("ok"):
                    failures.append("post-stress readiness failed")

                report = {
                    "schema": "szl.estate-stress-report/v1",
                    "status": "PASS" if not failures else "FAIL",
                    "requests": args.requests,
                    "concurrency": args.concurrency,
                    "elapsed_seconds": round(elapsed, 3),
                    "throughput_rps": round(throughput, 2),
                    "status_counts": status_counts,
                    "error_count": len(errors),
                    "error_rate": round(error_rate, 6),
                    "sample_errors": errors[:10],
                    "latency_ms": {
                        "min": round(latencies[0], 2),
                        "p50": round(percentile(latencies, 0.50), 2),
                        "p95": round(p95_ms, 2),
                        "p99": round(percentile(latencies, 0.99), 2),
                        "max": round(latencies[-1], 2),
                    },
                    "response_bytes": sum(item[2] for item in results),
                    "post_stress_ready": post_ready,
                    "threshold_failures": failures,
                }
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
