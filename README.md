# SecurityDriftLab-Auto

SecurityDriftLab-Auto is an automated research framework for studying **Security Drift in Prompt Evolution**: how iterative prompt refinement changes the security posture of AI-generated software.

It supports cybersecurity task generation, prompt revision generation, optional OpenAI API execution, generated code storage, static vulnerability scanning with Bandit and Semgrep, Security Drift Index (SDI) computation, CSV exports for journal-paper tables and figures, and a Streamlit dashboard for experiments.

## Quick Start

```bash
unzip SecurityDriftLab-Auto.zip
cd SecurityDriftLab-Auto
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
streamlit run app/app.py
```

Then open `http://localhost:8501`.

## Optional API Use

Add your API key to `.env`:

```env
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4.1-mini
```

If no API key is provided, the system still works in manual mode: generate prompts, paste outputs, run scans, and compute SDI.

## Main Workflow

1. Load or generate cybersecurity tasks.
2. Generate prompt revisions for each task.
3. Run prompts automatically through OpenAI or paste model output manually.
4. Save generated code artifacts.
5. Run Bandit and/or Semgrep scans.
6. Compute Security Drift Index across revisions.
7. Export tables for the paper.

## Security Drift Index

For revision *i*:

```text
SDI(i) = (NV + SR + ΔS) - (VR + SI)
```

where NV is newly introduced vulnerabilities, SR is security regressions, ΔS is increase in cumulative vulnerability severity, VR is removed vulnerabilities, and SI is security improvements. Positive SDI means security deterioration; negative SDI means security improvement.

## Recommended Journal-Scale Experiment

```text
100 tasks × 4 revisions × 3 models = 1200 generated artifacts
```

Suggested categories are Authentication and Access Control, Input Validation and Data Handling, Web Application Security, Secure Coding Practices, and Applied Cryptography.

## Disclaimer

This tool is for research and defensive software security evaluation only. Do not use it to generate, deploy, or test malicious code against systems you do not own or have permission to assess.



## One-Button Full Pipeline

The updated app includes a **One-Button Pipeline** tab.

Click:

```text
Run Full Pipeline
```

to automatically:

1. seed tasks if needed,
2. generate prompt revisions,
3. call OpenAI if `OPENAI_API_KEY` is configured,
4. save generated outputs,
5. scan outputs with Bandit/Semgrep,
6. compute Security Drift Index (SDI),
7. export CSV tables.

If you do not have API credits, use manual mode: save prompts, paste generated outputs, then click:

```text
Scan All Outputs + Compute SDI + Export
```

in the **Scan & SDI** tab.



## Why SDI May Be Zero

SDI can be zero when scanners find no vulnerabilities, or when every revision has the same vulnerability profile. This version adds a built-in heuristic scanner that detects common insecure patterns such as hardcoded secrets, SQL string concatenation, command injection, weak hashing, insecure randomness, unsafe deserialization, path traversal, debug mode, and plain password storage.

Keep **Run built-in heuristic scanner** enabled if Bandit/Semgrep return empty results.



## Stronger Journal-Scale Experiment

This version strengthens the study design.

Changes included:

- aggressive prompt revision strategy
- 100-task and 200-task seed options
- multi-model full-pipeline execution
- model-level SDI exports
- scanner distribution exports
- CWE and severity distribution exports

Recommended journal-scale run:

```text
200 tasks × 4 revisions × 3 models = 2400 generated artifacts
```

Recommended prompt revision design:

- Revision 1: basic implementation
- Revision 2: feature expansion
- Revision 3: performance/developer convenience
- Revision 4: production security hardening

This design intentionally creates more realistic security movement across revisions, including possible security deterioration during convenience/performance optimization and recovery during hardening.

## Install External Scanners

The heuristic scanner is enabled by default. For stronger research results, also install Bandit and Semgrep:

```bash
./scripts/install_scanners.sh
```

Then enable both scanner checkboxes in the Streamlit UI.
