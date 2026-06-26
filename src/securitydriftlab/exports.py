from pathlib import Path
from .db import fetch_df

def export_all():
    outdir = Path("data/exports")
    outdir.mkdir(parents=True, exist_ok=True)

    tables = {
        "tasks.csv": "SELECT * FROM tasks",
        "prompts.csv": "SELECT * FROM prompts",
        "outputs.csv": "SELECT * FROM outputs",
        "scans.csv": "SELECT * FROM scans",
        "sdi.csv": "SELECT * FROM sdi",
    }

    paths = []
    for fname, query in tables.items():
        df = fetch_df(query)
        path = outdir / fname
        df.to_csv(path, index=False)
        paths.append(str(path))

    sdi = fetch_df("SELECT * FROM sdi")
    if not sdi.empty:
        agg_map = {
            "records": ("sdi", "count"),
            "avg_sdi": ("sdi", "mean"),
            "avg_swsdi": ("swsdi", "mean"),
            "avg_srr": ("srr", "mean"),
            "avg_vc": ("vc", "mean"),
            "avg_new_vulns": ("new_vulns", "mean"),
            "avg_removed_vulns": ("removed_vulns", "mean"),
            "avg_severity_delta": ("severity_delta", "mean"),
        }

        cat = fetch_df("""
            SELECT sdi.*, tasks.category
            FROM sdi JOIN tasks ON sdi.task_id = tasks.task_id
        """)
        if not cat.empty:
            cat_summary = cat.groupby("category", as_index=False).agg(**agg_map)
            cat_summary.to_csv(outdir / "table_category_sdi.csv", index=False)
            paths.append(str(outdir / "table_category_sdi.csv"))

        rev_summary = sdi.groupby("revision", as_index=False).agg(**agg_map)
        rev_summary.to_csv(outdir / "table_revision_sdi.csv", index=False)
        paths.append(str(outdir / "table_revision_sdi.csv"))

        model_summary = sdi.groupby("model", as_index=False).agg(**agg_map)
        model_summary.to_csv(outdir / "table_model_sdi.csv", index=False)
        paths.append(str(outdir / "table_model_sdi.csv"))

    scans = fetch_df("SELECT * FROM scans")
    if not scans.empty:
        severity_summary = scans.groupby(["severity"], as_index=False).size()
        severity_summary.to_csv(outdir / "table_severity_distribution.csv", index=False)
        paths.append(str(outdir / "table_severity_distribution.csv"))

        cwe_summary = scans.groupby(["cwe"], as_index=False).size().sort_values("size", ascending=False)
        cwe_summary.to_csv(outdir / "table_cwe_distribution.csv", index=False)
        paths.append(str(outdir / "table_cwe_distribution.csv"))

        scanner_summary = scans.groupby(["scanner"], as_index=False).size()
        scanner_summary.to_csv(outdir / "table_scanner_distribution.csv", index=False)
        paths.append(str(outdir / "table_scanner_distribution.csv"))

    return paths
