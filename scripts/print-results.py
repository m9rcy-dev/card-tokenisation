#!/usr/bin/env python3
"""
Print a formatted summary table of all load test results found in
target/load-test-results/.

Usage:
    python3 scripts/print-results.py              # all results
    python3 scripts/print-results.py 1k           # filter by scale label
    make results                                   # same as above via Makefile
"""

import json
import glob
import sys
import os
from pathlib import Path


def load_results(scale_filter=None):
    pattern = str(Path("target") / "load-test-results" / "*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        return []

    results = []
    for f in files:
        try:
            with open(f) as fh:
                d = json.load(fh)
            if scale_filter:
                # e.g. "1k" matches test names containing "1K" or "1000"
                needle = scale_filter.upper()
                if needle not in d.get("testName", "").upper():
                    continue
            results.append(d)
        except (json.JSONDecodeError, KeyError):
            pass
    return results


def rps(d):
    ms = d.get("wallClockMs", 0)
    return int(d["totalRequests"] / (ms / 1000)) if ms > 0 else 0


def status(d):
    return "PASS" if d.get("errorCount", 1) == 0 else "FAIL"


def print_table(results):
    col = "{:<10}  {:>7}  {:>6}  {:>7}  {:>7}  {:>7}  {:>7}  {:>6}  {:>8}  {:>4}"
    header = col.format(
        "Test", "Reqs", "RPS", "p50 ms", "p95 ms", "p99 ms", "max ms",
        "Errors", "Heap MB", "Pass"
    )
    sep = "-" * len(header)

    print(sep)
    print(header)
    print(sep)

    for d in results:
        print(col.format(
            d.get("testName", "?"),
            d.get("totalRequests", 0),
            rps(d),
            d.get("p50Ms", 0),
            d.get("p95Ms", 0),
            d.get("p99Ms", 0),
            d.get("maxMs", 0),
            d.get("errorCount", 0),
            d.get("heapGrowthMb", 0),
            status(d),
        ))

    print(sep)

    # Summary line
    total_reqs = sum(d.get("totalRequests", 0) for d in results)
    total_errors = sum(d.get("errorCount", 0) for d in results)
    passes = sum(1 for d in results if d.get("errorCount", 0) == 0)
    print(f"\n  {len(results)} test(s)  |  {total_reqs:,} total requests  |  "
          f"{total_errors} errors  |  {passes}/{len(results)} passed\n")


def main():
    scale_filter = sys.argv[1] if len(sys.argv) > 1 else None

    # Resolve paths relative to the project root (one level up from this script)
    script_dir = Path(__file__).parent
    os.chdir(script_dir.parent)

    results = load_results(scale_filter)

    if not results:
        label = f" matching '{scale_filter}'" if scale_filter else ""
        print(f"\n  No load test results found{label}.")
        print("  Run: make load-test [SCALE=1k|5k|10k|20k|50k]\n")
        sys.exit(0)

    print()
    if scale_filter:
        print(f"  Load test results — scale filter: {scale_filter}")
    else:
        print("  Load test results — all runs")
    print()
    print_table(results)


if __name__ == "__main__":
    main()
