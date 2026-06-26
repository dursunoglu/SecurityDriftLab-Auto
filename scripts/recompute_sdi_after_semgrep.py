#!/usr/bin/env python3
"""
Recompute SDI and export tables after batch Semgrep import.

Run from project root:
    python scripts/recompute_sdi_after_semgrep.py
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

from securitydriftlab.db import init_db
from securitydriftlab.sdi import compute_all_sdi
from securitydriftlab.exports import export_all

init_db()
rows = compute_all_sdi()
paths = export_all()

print(f"Computed {len(rows)} SDI records.")
print("Exported:")
for p in paths:
    print(p)
