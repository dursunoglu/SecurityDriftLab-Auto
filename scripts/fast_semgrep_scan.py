#!/usr/bin/env python3
"""
Fast Batch Semgrep Scanner for SecurityDriftLab-Auto.

Run from project root:
    python scripts/fast_semgrep_scan.py --config auto

This is much faster than running Semgrep once per generated file.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

from securitydriftlab.db import get_conn, init_db, insert_scan


def normalize_path(p):
    return str(Path(p).resolve())


def load_outputs_map():
    conn = get_conn()
    rows = conn.execute(
        "SELECT task_id, model, revision, file_path FROM outputs"
    ).fetchall()
    conn.close()

    mapping = {}
    for row in rows:
        mapping[normalize_path(row["file_path"])] = {
            "task_id": row["task_id"],
            "model": row["model"],
            "revision": int(row["revision"]),
            "file_path": row["file_path"],
        }
    return mapping


def clear_old_semgrep():
    conn = get_conn()
    conn.execute("DELETE FROM scans WHERE scanner='semgrep'")
    conn.commit()
    conn.close()


def cwe_from_semgrep(result):
    metadata = (result.get("extra", {}) or {}).get("metadata", {}) or {}
    for key in ["cwe", "cwe2022-top25", "cwe2021-top25"]:
        if key in metadata:
            val = metadata[key]
            if isinstance(val, list):
                return ",".join(str(x) for x in val)
            return str(val)

    text = json.dumps(metadata)
    match = re.search(r"CWE-\d+", text)
    return match.group(0) if match else ""


def severity_from_semgrep(result):
    sev = str((result.get("extra", {}) or {}).get("severity", "LOW")).upper()
    if sev not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "LOW"
    return sev


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--outputs", default="data/outputs")
    parser.add_argument("--config", default="auto")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--jobs", default="4")
    parser.add_argument("--keep-old", action="store_true")
    args = parser.parse_args()

    init_db()

    outputs_dir = Path(args.outputs)
    if not outputs_dir.exists():
        raise FileNotFoundError(f"Outputs directory not found: {outputs_dir}")

    outputs_map = load_outputs_map()
    print(f"Loaded {len(outputs_map)} output file mappings from database.")

    if not args.keep_old:
        clear_old_semgrep()
        print("Cleared old Semgrep findings.")

    cmd = [
        "semgrep",
        "--config", args.config,
        "--json",
        "--metrics", "off",
        "--disable-version-check",
        "--timeout", str(args.timeout),
        "--jobs", str(args.jobs),
        str(outputs_dir),
    ]

    print("Running Semgrep once in batch mode:")
    print(" ".join(cmd))

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.stderr.strip():
        print("\nSemgrep stderr preview:")
        print(result.stderr[:4000])

    if not result.stdout.strip():
        raise RuntimeError("Semgrep produced no JSON output.")

    data = json.loads(result.stdout)

    imported = 0
    skipped = 0

    for item in data.get("results", []):
        path = normalize_path(item.get("path", ""))
        meta = outputs_map.get(path)

        if not meta:
            skipped += 1
            continue

        insert_scan(
            task_id=meta["task_id"],
            model=meta["model"],
            revision=meta["revision"],
            scanner="semgrep",
            finding_id=item.get("check_id", "SEMGRP_UNKNOWN"),
            cwe=cwe_from_semgrep(item),
            severity=severity_from_semgrep(item),
            message=(item.get("extra", {}) or {}).get("message", ""),
            file_path=meta["file_path"],
        )
        imported += 1

    print("\nDone.")
    print(f"Semgrep findings in JSON: {len(data.get('results', []))}")
    print(f"Imported findings: {imported}")
    print(f"Skipped findings without DB mapping: {skipped}")
    print("\nNow run:")
    print("python scripts/recompute_sdi_after_semgrep.py")


if __name__ == "__main__":
    main()
