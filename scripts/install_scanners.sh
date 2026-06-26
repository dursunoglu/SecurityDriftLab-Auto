#!/usr/bin/env bash
set -e
source .venv/bin/activate 2>/dev/null || true
pip install bandit semgrep
echo "Installed Bandit and Semgrep."
