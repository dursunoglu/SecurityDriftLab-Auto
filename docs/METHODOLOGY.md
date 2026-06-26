# Methodology

## Research Objective

This framework measures how iterative prompt refinement changes the security posture of AI-generated software.

## Recommended Experimental Design

The recommended journal-scale design is:

```text
200 tasks × 4 revisions × 3 models = 2400 generated artifacts
```

## Prompt Revision Strategy

Revision 1: Basic implementation focused on functional correctness.

Revision 2: Feature expansion, adding realistic application behavior, configuration, and edge cases.

Revision 3: Performance and developer convenience, encouraging concise and direct implementation patterns.

Revision 4: Production hardening, explicitly requiring OWASP-aligned secure coding, safe defaults, secure randomness, input validation, and avoidance of dangerous patterns.

This strategy is designed to produce measurable security movement across revisions.

## Security Drift

Security Drift is the cumulative change in software security caused by prompt evolution.

## Security Events

The framework tracks vulnerability introduction, vulnerability removal, severity change, and security regression.

## Research Questions

RQ1: How does iterative prompt refinement affect the security posture of AI-generated software?

RQ2: Which cybersecurity task categories experience the greatest Security Drift?

RQ3: How frequently are vulnerabilities introduced, removed, or reintroduced during prompt evolution?

RQ4: Do different LLMs exhibit different Security Drift characteristics under identical prompt evolution scenarios?

RQ5: Can prompt evolution patterns be used to predict future security regressions?
