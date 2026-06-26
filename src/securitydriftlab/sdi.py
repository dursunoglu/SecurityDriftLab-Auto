from datetime import datetime
from .db import get_conn, fetch_df, init_db

SEVERITY_WEIGHTS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 5,
    "UNDEFINED": 1,
}

def normalize_severity(value):
    sev = str(value or "LOW").upper().strip()
    if sev not in SEVERITY_WEIGHTS:
        return "LOW"
    return sev

def vuln_signature(row):
    cwe = str(row.get("cwe") or "").strip()
    finding_id = str(row.get("finding_id") or "").strip()
    scanner = str(row.get("scanner") or "").strip()
    return f"{scanner}:{cwe}:{finding_id}"

def build_signature_map(df):
    sig_map = {}
    if df is None or df.empty:
        return sig_map

    for _, row in df.iterrows():
        sig = vuln_signature(row)
        sev = normalize_severity(row.get("severity"))
        weight = SEVERITY_WEIGHTS.get(sev, 1)
        if sig not in sig_map or weight > sig_map[sig]["weight"]:
            sig_map[sig] = {"severity": sev, "weight": weight}
    return sig_map

def count_severity(sig_map, signatures):
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sig in signatures:
        sev = sig_map.get(sig, {}).get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1
    return counts

def weighted_score(sig_map, signatures):
    return sum(sig_map.get(sig, {}).get("weight", 1) for sig in signatures)

def compute_sdi_for(task_id, model, revision):
    init_db()

    if revision <= 1:
        return None

    scans = fetch_df(f"""
        SELECT * FROM scans
        WHERE task_id='{task_id}' AND model='{model}' AND revision IN ({revision-1}, {revision})
    """)

    prev = scans[scans["revision"] == revision - 1]
    curr = scans[scans["revision"] == revision]

    prev_map = build_signature_map(prev)
    curr_map = build_signature_map(curr)

    prev_set = set(prev_map.keys())
    curr_set = set(curr_map.keys())

    new_set = curr_set - prev_set
    removed_set = prev_set - curr_set

    new_vulns = len(new_set)
    removed_vulns = len(removed_set)
    prev_vulns = len(prev_set)
    curr_vulns = len(curr_set)

    older = fetch_df(f"""
        SELECT * FROM scans
        WHERE task_id='{task_id}' AND model='{model}' AND revision < {revision-1}
    """)
    older_map = build_signature_map(older)
    older_set = set(older_map.keys())
    regressions = len(new_set.intersection(older_set))

    prev_score = weighted_score(prev_map, prev_set)
    curr_score = weighted_score(curr_map, curr_set)
    new_weighted = weighted_score(curr_map, new_set)
    removed_weighted = weighted_score(prev_map, removed_set)
    severity_delta = curr_score - prev_score

    improvements = max(0, removed_vulns)

    # Original net Security Drift Index retained.
    sdi = (new_vulns + regressions + max(0, severity_delta)) - (removed_vulns + improvements)

    # Severity-Weighted Security Drift.
    swsdi = new_weighted - removed_weighted

    # Security Regression Rate.
    srr = new_vulns / (prev_vulns + 1)

    # Vulnerability Churn.
    vc = new_vulns + removed_vulns

    new_counts = count_severity(curr_map, new_set)
    removed_counts = count_severity(prev_map, removed_set)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM sdi WHERE task_id=? AND model=? AND revision=?",
        (task_id, model, revision),
    )
    cur.execute("""
        INSERT INTO sdi (
            task_id, model, revision,
            new_vulns, removed_vulns, severity_delta,
            regressions, improvements, sdi,
            swsdi, srr, vc,
            prev_vulns, curr_vulns,
            new_low, new_medium, new_high, new_critical,
            removed_low, removed_medium, removed_high, removed_critical,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        task_id,
        model,
        revision,
        new_vulns,
        removed_vulns,
        severity_delta,
        regressions,
        improvements,
        sdi,
        swsdi,
        srr,
        vc,
        prev_vulns,
        curr_vulns,
        new_counts["LOW"],
        new_counts["MEDIUM"],
        new_counts["HIGH"],
        new_counts["CRITICAL"],
        removed_counts["LOW"],
        removed_counts["MEDIUM"],
        removed_counts["HIGH"],
        removed_counts["CRITICAL"],
        datetime.utcnow().isoformat(),
    ))
    conn.commit()
    conn.close()

    return {
        "task_id": task_id,
        "model": model,
        "revision": revision,
        "new_vulns": new_vulns,
        "removed_vulns": removed_vulns,
        "severity_delta": severity_delta,
        "regressions": regressions,
        "improvements": improvements,
        "sdi": sdi,
        "swsdi": swsdi,
        "srr": srr,
        "vc": vc,
        "prev_vulns": prev_vulns,
        "curr_vulns": curr_vulns,
    }

def compute_all_sdi():
    init_db()
    outputs = fetch_df("""
        SELECT DISTINCT task_id, model, revision
        FROM outputs
        ORDER BY task_id, model, revision
    """)
    rows = []
    for _, row in outputs.iterrows():
        revision = int(row["revision"])
        if revision > 1:
            result = compute_sdi_for(row["task_id"], row["model"], revision)
            if result:
                rows.append(result)
    return rows
