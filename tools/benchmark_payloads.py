"""Simple payload benchmark harness.

Usage:
  python tools/benchmark_payloads.py --target https://example.com --output benchmark.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


def run_command(cmd: list[str]) -> tuple[int, float, str]:
    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start
    return proc.returncode, elapsed, proc.stdout + "\n" + proc.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark AKHA profiles on a single target")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--output", default="benchmark_payloads.json", help="Output JSON file")
    args = parser.parse_args()

    profiles = ["quick", "balanced", "deep"]
    results = []

    for profile in profiles:
        out_dir = Path("output") / f"bench_{profile}"
        cmd = [
            "akha-xss", "scan",
            "--url", args.target,
            "--mode", "url",
            "--profile", profile,
            "--format", "json",
            "--output", str(out_dir),
            "--quiet",
        ]
        code, elapsed, output = run_command(cmd)
        results.append({
            "profile": profile,
            "exit_code": code,
            "elapsed_seconds": round(elapsed, 3),
            "log_excerpt": output[-1200:],
        })

    payload = {
        "target": args.target,
        "results": results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Benchmark complete: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
