#!/usr/bin/env python3
"""
Security Drift Statistical Analysis

Input:
    data/exports/sdi.csv
    data/exports/tasks.csv

Outputs:
    data/exports/stats/
"""

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


def ensure_numeric(df, cols):
    for col in cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def bootstrap_ci(values, n_boot=10000, ci=95, seed=42):
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) == 0:
        return np.nan, np.nan

    rng = np.random.default_rng(seed)
    means = []
    for _ in range(n_boot):
        sample = rng.choice(values, size=len(values), replace=True)
        means.append(np.mean(sample))

    alpha = (100 - ci) / 2
    return np.percentile(means, alpha), np.percentile(means, 100 - alpha)


def kruskal_eta_squared(groups, h_stat, n_total):
    k = len(groups)
    if n_total <= k:
        return np.nan
    return max(0.0, (h_stat - k + 1) / (n_total - k))


def effect_interpretation(eta):
    if pd.isna(eta):
        return "NA"
    if eta < 0.01:
        return "negligible"
    if eta < 0.06:
        return "small"
    if eta < 0.14:
        return "medium"
    return "large"


def descriptive_stats(df, group_col, value_col="sdi"):
    rows = []
    for group, sub in df.groupby(group_col):
        vals = pd.to_numeric(sub[value_col], errors="coerce").dropna().values
        ci_low, ci_high = bootstrap_ci(vals)
        rows.append({
            group_col: group,
            "n": len(vals),
            "mean": np.mean(vals) if len(vals) else np.nan,
            "median": np.median(vals) if len(vals) else np.nan,
            "std": np.std(vals, ddof=1) if len(vals) > 1 else np.nan,
            "min": np.min(vals) if len(vals) else np.nan,
            "max": np.max(vals) if len(vals) else np.nan,
            "ci95_low": ci_low,
            "ci95_high": ci_high,
        })
    return pd.DataFrame(rows).sort_values("mean", ascending=False)


def run_kruskal(df, group_col, value_col="sdi"):
    groups = []
    for _, sub in df.groupby(group_col):
        vals = pd.to_numeric(sub[value_col], errors="coerce").dropna().values
        if len(vals) > 0:
            groups.append(vals)

    if len(groups) < 2:
        return {
            "factor": group_col,
            "groups": len(groups),
            "n": sum(len(g) for g in groups),
            "H": np.nan,
            "p_value": np.nan,
            "eta_squared": np.nan,
            "effect": "NA",
            "note": "Fewer than two valid groups"
        }

    h_stat, p_value = kruskal(*groups)
    eta = kruskal_eta_squared(groups, h_stat, sum(len(g) for g in groups))
    return {
        "factor": group_col,
        "groups": len(groups),
        "n": sum(len(g) for g in groups),
        "H": h_stat,
        "p_value": p_value,
        "eta_squared": eta,
        "effect": effect_interpretation(eta),
        "note": ""
    }


def run_dunn(df, group_col, value_col="sdi"):
    if not HAS_POSTHOCS:
        return None
    tmp = df[[group_col, value_col]].copy()
    tmp[value_col] = pd.to_numeric(tmp[value_col], errors="coerce")
    tmp = tmp.dropna()
    if tmp[group_col].nunique() < 2:
        return None
    return sp.posthoc_dunn(tmp, val_col=value_col, group_col=group_col, p_adjust="bonferroni")


def format_p(p):
    if pd.isna(p):
        return "NA"
    if p < 0.001:
        return "<0.001"
    return f"{p:.4f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdi", default="data/exports/sdi.csv")
    parser.add_argument("--tasks", default="data/exports/tasks.csv")
    parser.add_argument("--out", default="data/exports/stats")
    args = parser.parse_args()

    sdi_path = Path(args.sdi)
    tasks_path = Path(args.tasks)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not sdi_path.exists():
        raise FileNotFoundError(f"Could not find SDI file: {sdi_path}")

    sdi = pd.read_csv(sdi_path)
    sdi = ensure_numeric(sdi, ["revision", "sdi", "new_vulns", "removed_vulns", "severity_delta", "regressions", "improvements"])

    if tasks_path.exists():
        tasks = pd.read_csv(tasks_path)
        if "task_id" in sdi.columns and "task_id" in tasks.columns and "category" in tasks.columns:
            df = sdi.merge(tasks[["task_id", "category"]].drop_duplicates(), on="task_id", how="left")
        else:
            df = sdi.copy()
            warnings.warn("tasks.csv exists but required columns are missing. Category tests skipped.")
    else:
        df = sdi.copy()
        warnings.warn("tasks.csv not found. Category tests skipped.")

    for col in ["model", "revision", "sdi"]:
        if col not in df.columns:
            raise ValueError(f"Missing required column in sdi.csv: {col}")

    desc_model = descriptive_stats(df, "model")
    desc_revision = descriptive_stats(df, "revision")
    desc_model.to_csv(out_dir / "descriptive_by_model.csv", index=False)
    desc_revision.to_csv(out_dir / "descriptive_by_revision.csv", index=False)

    has_category = "category" in df.columns and df["category"].notna().any()
    if has_category:
        desc_category = descriptive_stats(df, "category")
        desc_category.to_csv(out_dir / "descriptive_by_category.csv", index=False)
    else:
        desc_category = pd.DataFrame()

    tests = [run_kruskal(df, "model"), run_kruskal(df, "revision")]
    if has_category:
        tests.append(run_kruskal(df.dropna(subset=["category"]), "category"))

    tests_df = pd.DataFrame(tests)
    tests_df.to_csv(out_dir / "kruskal_tests.csv", index=False)

    if HAS_POSTHOCS:
        dunn_model = run_dunn(df, "model")
        if dunn_model is not None:
            dunn_model.to_csv(out_dir / "dunn_model.csv")

        dunn_revision = run_dunn(df, "revision")
        if dunn_revision is not None:
            dunn_revision.to_csv(out_dir / "dunn_revision.csv")

        if has_category:
            dunn_category = run_dunn(df.dropna(subset=["category"]), "category")
            if dunn_category is not None:
                dunn_category.to_csv(out_dir / "dunn_category.csv")
    else:
        (out_dir / "POSTHOCS_NOT_RUN.txt").write_text(
            "scikit-posthocs is not installed. Install it with: pip install scikit-posthocs\n"
        )

    desc_model[["model", "mean", "ci95_low", "ci95_high", "n"]].to_csv(out_dir / "bootstrap_ci_model.csv", index=False)
    desc_revision[["revision", "mean", "ci95_low", "ci95_high", "n"]].to_csv(out_dir / "bootstrap_ci_revision.csv", index=False)
    if has_category:
        desc_category[["category", "mean", "ci95_low", "ci95_high", "n"]].to_csv(out_dir / "bootstrap_ci_category.csv", index=False)

    lines = []
    lines.append("Security Drift Statistical Analysis Summary")
    lines.append("=" * 52)
    lines.append("")
    lines.append(f"Total SDI records: {len(df)}")
    lines.append(f"Models: {df['model'].nunique()}")
    lines.append(f"Revisions analyzed: {sorted(df['revision'].dropna().unique().tolist())}")
    if has_category:
        lines.append(f"Categories: {df['category'].nunique()}")
    lines.append("")

    lines.append("Descriptive Results by Model")
    lines.append("-" * 52)
    for _, row in desc_model.iterrows():
        lines.append(
            f"{row['model']}: mean SDI={row['mean']:.4f}, "
            f"95% CI [{row['ci95_low']:.4f}, {row['ci95_high']:.4f}], n={int(row['n'])}"
        )
    lines.append("")

    lines.append("Descriptive Results by Revision")
    lines.append("-" * 52)
    for _, row in desc_revision.iterrows():
        lines.append(
            f"Revision {int(row['revision'])}: mean SDI={row['mean']:.4f}, "
            f"95% CI [{row['ci95_low']:.4f}, {row['ci95_high']:.4f}], n={int(row['n'])}"
        )
    lines.append("")

    if has_category:
        lines.append("Descriptive Results by Category")
        lines.append("-" * 52)
        for _, row in desc_category.iterrows():
            lines.append(
                f"{row['category']}: mean SDI={row['mean']:.4f}, "
                f"95% CI [{row['ci95_low']:.4f}, {row['ci95_high']:.4f}], n={int(row['n'])}"
            )
        lines.append("")

    lines.append("Kruskal-Wallis Tests")
    lines.append("-" * 52)
    for _, row in tests_df.iterrows():
        lines.append(
            f"{row['factor']}: H={row['H']:.4f}, p={format_p(row['p_value'])}, "
            f"eta^2={row['eta_squared']:.4f}, effect={row['effect']}, n={int(row['n'])}"
        )
    lines.append("")
    lines.append("Paper-ready wording template")
    lines.append("-" * 52)
    lines.append(
        "Because SDI values were not assumed to be normally distributed, "
        "Kruskal-Wallis tests were used to compare Security Drift across models, "
        "prompt revisions, and task categories. Effect sizes were estimated using "
        "Kruskal-Wallis eta-squared, and 95% confidence intervals were computed "
        "using bootstrap resampling."
    )
    lines.append("")
    for _, row in tests_df.iterrows():
        lines.append(
            f"For {row['factor']}, the Kruskal-Wallis test produced "
            f"H={row['H']:.3f}, p={format_p(row['p_value'])}, "
            f"eta^2={row['eta_squared']:.3f}, indicating a {row['effect']} effect."
        )

    (out_dir / "paper_summary.txt").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\nSaved statistical outputs to: {out_dir}")


if __name__ == "__main__":
    main()
