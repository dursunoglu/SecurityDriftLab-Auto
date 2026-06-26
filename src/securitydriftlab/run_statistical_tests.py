#!/usr/bin/env python3
import argparse
from pathlib import Path
import warnings
import numpy as np
import pandas as pd
from scipy.stats import kruskal

try:
    import scikit_posthocs as sp
    HAS_POSTHOCS = True
except Exception:
    HAS_POSTHOCS = False

METRICS = {
    "sdi": "Security Drift Index",
    "swsdi": "Severity-Weighted Security Drift",
    "srr": "Security Regression Rate",
    "vc": "Vulnerability Churn",
}

def bootstrap_ci(values, n_boot=10000, seed=42):
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) == 0:
        return np.nan, np.nan
    rng = np.random.default_rng(seed)
    means = [np.mean(rng.choice(values, size=len(values), replace=True)) for _ in range(n_boot)]
    return np.percentile(means, 2.5), np.percentile(means, 97.5)

def eta_squared(groups, h, n):
    k = len(groups)
    if n <= k:
        return np.nan
    return max(0.0, (h - k + 1) / (n - k))

def effect_label(e):
    if pd.isna(e):
        return "NA"
    if e < 0.01:
        return "negligible"
    if e < 0.06:
        return "small"
    if e < 0.14:
        return "medium"
    return "large"

def fmt_p(p):
    if pd.isna(p):
        return "NA"
    return "<0.001" if p < 0.001 else f"{p:.4f}"

def desc(df, group_col, metric):
    rows = []
    for group, sub in df.groupby(group_col):
        vals = pd.to_numeric(sub[metric], errors="coerce").dropna().values
        lo, hi = bootstrap_ci(vals)
        rows.append({
            group_col: group,
            "metric": metric,
            "n": len(vals),
            "mean": np.mean(vals) if len(vals) else np.nan,
            "median": np.median(vals) if len(vals) else np.nan,
            "std": np.std(vals, ddof=1) if len(vals) > 1 else np.nan,
            "ci95_low": lo,
            "ci95_high": hi,
        })
    return pd.DataFrame(rows).sort_values("mean", ascending=False)

def kw(df, group_col, metric):
    groups = []
    for _, sub in df.groupby(group_col):
        vals = pd.to_numeric(sub[metric], errors="coerce").dropna().values
        if len(vals):
            groups.append(vals)
    if len(groups) < 2:
        return {"metric": metric, "factor": group_col, "groups": len(groups), "n": sum(len(g) for g in groups),
                "H": np.nan, "p_value": np.nan, "eta_squared": np.nan, "effect": "NA"}
    h, p = kruskal(*groups)
    e = eta_squared(groups, h, sum(len(g) for g in groups))
    return {"metric": metric, "factor": group_col, "groups": len(groups), "n": sum(len(g) for g in groups),
            "H": h, "p_value": p, "eta_squared": e, "effect": effect_label(e)}

def dunn(df, group_col, metric):
    if not HAS_POSTHOCS:
        return None
    tmp = df[[group_col, metric]].copy()
    tmp[metric] = pd.to_numeric(tmp[metric], errors="coerce")
    tmp = tmp.dropna()
    if tmp[group_col].nunique() < 2:
        return None
    return sp.posthoc_dunn(tmp, val_col=metric, group_col=group_col, p_adjust="bonferroni")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdi", default="data/exports/sdi.csv")
    ap.add_argument("--tasks", default="data/exports/tasks.csv")
    ap.add_argument("--out", default="data/exports/stats")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    sdi = pd.read_csv(args.sdi)
    tasks_path = Path(args.tasks)

    if tasks_path.exists():
        tasks = pd.read_csv(tasks_path)
        if "task_id" in sdi.columns and "task_id" in tasks.columns and "category" in tasks.columns:
            df = sdi.merge(tasks[["task_id", "category"]].drop_duplicates(), on="task_id", how="left")
        else:
            df = sdi.copy()
            warnings.warn("tasks.csv missing required columns; category tests skipped.")
    else:
        df = sdi.copy()
        warnings.warn("tasks.csv not found; category tests skipped.")

    for c in ["model", "revision", "sdi"]:
        if c not in df.columns:
            raise ValueError(f"Missing required column: {c}")

    metrics = [m for m in METRICS if m in df.columns]
    has_category = "category" in df.columns and df["category"].notna().any()

    all_tests = []
    lines = ["Security Drift Statistical Analysis Summary", "=" * 60, f"Total records: {len(df)}", ""]

    for metric in metrics:
        mdir = out / metric
        mdir.mkdir(parents=True, exist_ok=True)

        desc(df, "model", metric).to_csv(mdir / "descriptive_by_model.csv", index=False)
        desc(df, "revision", metric).to_csv(mdir / "descriptive_by_revision.csv", index=False)
        if has_category:
            desc(df, "category", metric).to_csv(mdir / "descriptive_by_category.csv", index=False)

        tests = [kw(df, "model", metric), kw(df, "revision", metric)]
        if has_category:
            tests.append(kw(df.dropna(subset=["category"]), "category", metric))

        tests_df = pd.DataFrame(tests)
        tests_df.to_csv(mdir / "kruskal_tests.csv", index=False)
        all_tests.extend(tests)

        if HAS_POSTHOCS:
            for factor in ["model", "revision"] + (["category"] if has_category else []):
                res = dunn(df.dropna(subset=[factor]), factor, metric)
                if res is not None:
                    res.to_csv(mdir / f"dunn_{factor}.csv")

        lines.append(METRICS[metric])
        lines.append("-" * 60)
        for _, row in tests_df.iterrows():
            lines.append(f"{row['factor']}: H={row['H']:.4f}, p={fmt_p(row['p_value'])}, eta^2={row['eta_squared']:.4f}, effect={row['effect']}, n={int(row['n'])}")
        lines.append("")

    all_df = pd.DataFrame(all_tests)
    all_df.to_csv(out / "kruskal_tests_all_metrics.csv", index=False)

    lines.append("Paper-ready wording")
    lines.append("-" * 60)
    lines.append("Because metric values were not assumed to be normally distributed, Kruskal-Wallis tests were used to compare security-evolution metrics across models, prompt revisions, and task categories. Effect sizes were estimated using Kruskal-Wallis eta-squared, and 95% confidence intervals were computed using bootstrap resampling.")
    lines.append("")
    for _, row in all_df.iterrows():
        lines.append(f"For {METRICS.get(row['metric'], row['metric'])} by {row['factor']}, H={row['H']:.3f}, p={fmt_p(row['p_value'])}, eta^2={row['eta_squared']:.3f}, effect={row['effect']}.")

    (out / "paper_summary_all_metrics.txt").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))

if __name__ == "__main__":
    main()
