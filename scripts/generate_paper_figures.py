#!/usr/bin/env python3
"""
Generate publication-ready figures for the Security Drift paper.

Run from the SecurityDriftLab-Auto project root:

    python scripts/generate_paper_figures.py

Expected input files:
    data/exports/table_revision_sdi.csv
    data/exports/table_model_sdi.csv
    data/exports/table_category_sdi.csv
    data/exports/table_cwe_distribution.csv
    data/exports/table_severity_distribution.csv
    data/exports/table_scanner_distribution.csv
    data/exports/sdi.csv

Outputs are saved to:
    figures/

Dependencies:
    pip install pandas matplotlib numpy
"""

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

EXPORT_DIR = Path("data/exports")
FIG_DIR = Path("figures")
FIG_DIR.mkdir(exist_ok=True)


def savefig(name):
    png = FIG_DIR / f"{name}.png"
    pdf = FIG_DIR / f"{name}.pdf"
    plt.savefig(png, dpi=300, bbox_inches="tight")
    plt.savefig(pdf, bbox_inches="tight")
    plt.close()
    print(f"Saved {png}")
    print(f"Saved {pdf}")


def read_csv(name):
    path = EXPORT_DIR / name
    if not path.exists():
        print(f"Warning: missing {path}")
        return pd.DataFrame()
    return pd.read_csv(path)


def box(ax, x, y, w, h, text, fontsize=10):
    patch = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.03",
        linewidth=1.3,
        edgecolor="black",
        facecolor="white"
    )
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fontsize, wrap=True)
    return patch


def arrow(ax, x1, y1, x2, y2):
    arr = FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle="->",
        mutation_scale=14,
        linewidth=1.2,
        color="black"
    )
    ax.add_patch(arr)


def clean_axes(ax):
    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_frame_on(False)


def fig1_prompt_security_drift_motivation():
    fig, ax = plt.subplots(figsize=(10, 4.8))
    clean_axes(ax)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5)

    xs = [1.0, 4.0, 7.0]
    labels = ["Prompt\nRevision 1", "Prompt\nRevision 2", "Prompt\nRevision 3"]
    codes = ["Generated\nCode 1", "Generated\nCode 2", "Generated\nCode 3"]
    scans = ["Security\nFindings 1", "Security\nFindings 2", "Security\nFindings 3"]

    for x, p, c, s in zip(xs, labels, codes, scans):
        box(ax, x, 3.7, 1.7, 0.7, p)
        box(ax, x, 2.4, 1.7, 0.7, c)
        box(ax, x, 1.1, 1.7, 0.7, s)
        arrow(ax, x + 0.85, 3.7, x + 0.85, 3.1)
        arrow(ax, x + 0.85, 2.4, x + 0.85, 1.8)

    arrow(ax, 2.7, 4.05, 4.0, 4.05)
    arrow(ax, 5.7, 4.05, 7.0, 4.05)

    box(ax, 3.8, 0.05, 2.4, 0.65, "Security Drift", fontsize=11)
    arrow(ax, 1.85, 1.1, 4.2, 0.7)
    arrow(ax, 4.85, 1.1, 5.0, 0.7)
    arrow(ax, 7.85, 1.1, 5.8, 0.7)

    ax.set_title("Motivation: Prompt Evolution Induces Security Evolution", fontsize=13, pad=10)
    savefig("fig1_prompt_security_drift_motivation")


def fig2_sdaf_conceptual_framework():
    fig, ax = plt.subplots(figsize=(7, 7.5))
    clean_axes(ax)
    ax.set_xlim(0, 7)
    ax.set_ylim(0, 9)

    elements = [
        ("Prompt\nEvolution", 3.5, 8.0),
        ("Generated\nSoftware", 3.5, 6.7),
        ("Static Security\nAnalysis", 3.5, 5.4),
        ("Security Drift\nEngine", 3.5, 4.1),
        ("SDI  |  SW-SDI\nSRR  |  VC", 3.5, 2.7),
        ("Statistical\nEvaluation", 3.5, 1.3),
    ]

    for text, cx, cy in elements:
        box(ax, cx - 1.35, cy - 0.35, 2.7, 0.7, text)

    for i in range(len(elements) - 1):
        _, x1, y1 = elements[i]
        _, x2, y2 = elements[i + 1]
        arrow(ax, x1, y1 - 0.35, x2, y2 + 0.35)

    ax.set_title("Security Drift Analytics Framework (SDAF)", fontsize=13, pad=10)
    savefig("fig2_sdaf_conceptual_framework")


def fig3_securitydriftlab_architecture():
    fig, ax = plt.subplots(figsize=(11, 6.2))
    clean_axes(ax)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7)

    box(ax, 0.5, 5.8, 1.8, 0.7, "Benchmark\nTasks")
    box(ax, 0.5, 4.5, 1.8, 0.7, "Prompt\nGenerator")
    box(ax, 0.5, 3.2, 1.8, 0.7, "LLM\nInterface")
    box(ax, 0.5, 1.9, 1.8, 0.7, "Generated\nCode")

    arrow(ax, 1.4, 5.8, 1.4, 5.2)
    arrow(ax, 1.4, 4.5, 1.4, 3.9)
    arrow(ax, 1.4, 3.2, 1.4, 2.6)

    box(ax, 3.4, 4.7, 2.0, 0.7, "Bandit")
    box(ax, 3.4, 3.6, 2.0, 0.7, "Semgrep")
    box(ax, 3.4, 2.5, 2.0, 0.7, "Heuristic\nAnalyzer")
    arrow(ax, 2.3, 2.25, 3.4, 5.05)
    arrow(ax, 2.3, 2.25, 3.4, 3.95)
    arrow(ax, 2.3, 2.25, 3.4, 2.85)

    box(ax, 6.5, 3.6, 2.0, 0.8, "Vulnerability\nNormalizer")
    arrow(ax, 5.4, 5.05, 6.5, 4.05)
    arrow(ax, 5.4, 3.95, 6.5, 4.0)
    arrow(ax, 5.4, 2.85, 6.5, 3.95)

    box(ax, 9.5, 4.5, 2.0, 0.7, "Security Drift\nEngine")
    box(ax, 9.5, 3.2, 2.0, 0.7, "Statistics\nModule")
    box(ax, 9.5, 1.9, 2.0, 0.7, "CSV Tables\nand Figures")
    arrow(ax, 8.5, 4.0, 9.5, 4.85)
    arrow(ax, 10.5, 4.5, 10.5, 3.9)
    arrow(ax, 10.5, 3.2, 10.5, 2.6)

    ax.set_title("End-to-End Workflow of SecurityDriftLab-Auto", fontsize=13, pad=10)
    savefig("fig3_securitydriftlab_architecture")


def fig4_dataset_generation_workflow():
    fig, ax = plt.subplots(figsize=(10, 5.5))
    clean_axes(ax)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)

    box(ax, 0.6, 4.5, 1.7, 0.75, "Cybersecurity\nTask")
    box(ax, 3.0, 4.5, 1.7, 0.75, "Prompt\nRevision 1")
    box(ax, 5.4, 4.5, 1.7, 0.75, "Prompt\nRevision 2")
    box(ax, 7.8, 4.5, 1.7, 0.75, "Prompt\nRevision 3/4")

    arrow(ax, 2.3, 4.875, 3.0, 4.875)
    arrow(ax, 4.7, 4.875, 5.4, 4.875)
    arrow(ax, 7.1, 4.875, 7.8, 4.875)

    for x in [3.0, 5.4, 7.8]:
        box(ax, x, 2.9, 1.7, 0.75, "Generated\nArtifact")
        arrow(ax, x + 0.85, 4.5, x + 0.85, 3.65)
        box(ax, x, 1.35, 1.7, 0.75, "Security\nAnalysis")
        arrow(ax, x + 0.85, 2.9, x + 0.85, 2.1)

    box(ax, 4.6, 0.15, 2.4, 0.75, "Longitudinal\nMetric Dataset")
    arrow(ax, 3.85, 1.35, 5.3, 0.9)
    arrow(ax, 6.25, 1.35, 5.8, 0.9)
    arrow(ax, 8.65, 1.35, 6.3, 0.9)

    ax.set_title("Dataset Generation Workflow", fontsize=13, pad=10)
    savefig("fig4_dataset_generation_workflow")


def fig5_sdi_by_revision():
    df = read_csv("table_revision_sdi.csv")
    if df.empty or "revision" not in df.columns:
        return
    ycol = "avg_sdi" if "avg_sdi" in df.columns else "sdi"
    df = df.sort_values("revision")

    plt.figure(figsize=(6.5, 4.2))
    plt.plot(df["revision"], df[ycol], marker="o", linewidth=2)
    plt.axhline(0, linestyle="--", linewidth=1)
    plt.xlabel("Prompt Revision")
    plt.ylabel("Average SDI")
    plt.title("Security Drift Index Across Prompt Revisions")
    plt.grid(True, alpha=0.3)
    savefig("fig5_sdi_by_revision")


def fig6_metrics_by_revision():
    df = read_csv("table_revision_sdi.csv")
    if df.empty or "revision" not in df.columns:
        return
    df = df.sort_values("revision")

    metric_cols = [
        ("avg_sdi", "SDI"),
        ("avg_swsdi", "SW-SDI"),
        ("avg_srr", "SRR"),
        ("avg_vc", "VC"),
    ]

    plt.figure(figsize=(7.5, 4.8))
    plotted = False
    for col, label in metric_cols:
        if col in df.columns:
            vals = df[col].astype(float)
            if vals.abs().max() != 0:
                vals = vals / vals.abs().max()
            plt.plot(df["revision"], vals, marker="o", linewidth=2, label=label)
            plotted = True

    if not plotted:
        return

    plt.axhline(0, linestyle="--", linewidth=1)
    plt.xlabel("Prompt Revision")
    plt.ylabel("Normalized Metric Value")
    plt.title("Normalized SDAF Metrics Across Prompt Revisions")
    plt.legend()
    plt.grid(True, alpha=0.3)
    savefig("fig6_metrics_by_revision")


def fig7_security_drift_lifecycle():
    fig, ax = plt.subplots(figsize=(9, 6))
    clean_axes(ax)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)

    nodes = [
        ("Requirements", 1.0, 5.7),
        ("Prompt\nEngineering", 3.6, 5.7),
        ("Code\nGeneration", 6.2, 5.7),
        ("Security\nAnalysis", 8.0, 3.6),
        ("Prompt\nRefinement", 5.4, 1.5),
        ("Security\nDrift", 2.7, 1.5),
    ]

    for text, x, y in nodes:
        box(ax, x, y, 1.8, 0.75, text)

    arrow(ax, 2.8, 6.075, 3.6, 6.075)
    arrow(ax, 5.4, 6.075, 6.2, 6.075)
    arrow(ax, 8.0, 5.7, 8.6, 4.35)
    arrow(ax, 8.0, 3.6, 6.9, 2.25)
    arrow(ax, 5.4, 1.875, 4.5, 1.875)
    arrow(ax, 2.7, 2.25, 1.9, 5.7)

    ax.text(5.0, 3.4, "Continuous secure\nAI-assisted development", ha="center", va="center", fontsize=11)
    ax.set_title("Security Drift Lifecycle in AI-Assisted Development", fontsize=13, pad=10)
    savefig("fig7_security_drift_lifecycle")


def fig8_model_comparison():
    df = read_csv("table_model_sdi.csv")
    if df.empty or "model" not in df.columns:
        return

    ycol = "avg_sdi" if "avg_sdi" in df.columns else "sdi"
    df = df.sort_values(ycol, ascending=False)

    plt.figure(figsize=(7.5, 4.5))
    plt.bar(df["model"], df[ycol])
    plt.axhline(0, linestyle="--", linewidth=1)
    plt.xlabel("Model")
    plt.ylabel("Average SDI")
    plt.title("Average Security Drift by Language Model")
    plt.xticks(rotation=20, ha="right")
    plt.grid(axis="y", alpha=0.3)
    savefig("fig8_model_comparison")


def fig9_cwe_distribution():
    df = read_csv("table_cwe_distribution.csv")
    if df.empty:
        return

    count_col = "size" if "size" in df.columns else df.columns[-1]
    cwe_col = "cwe" if "cwe" in df.columns else df.columns[0]
    df = df[df[cwe_col].notna()]
    df = df.sort_values(count_col, ascending=False).head(10)

    plt.figure(figsize=(8, 4.8))
    plt.barh(df[cwe_col].astype(str), df[count_col])
    plt.gca().invert_yaxis()
    plt.xlabel("Finding Count")
    plt.ylabel("CWE")
    plt.title("Top CWE Categories Detected in Generated Software")
    plt.grid(axis="x", alpha=0.3)
    savefig("fig9_cwe_distribution")


def fig10_severity_distribution():
    df = read_csv("table_severity_distribution.csv")
    if df.empty:
        return

    count_col = "size" if "size" in df.columns else df.columns[-1]
    sev_col = "severity" if "severity" in df.columns else df.columns[0]

    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    df[sev_col] = df[sev_col].astype(str).str.upper()
    df["order"] = df[sev_col].apply(lambda x: order.index(x) if x in order else 99)
    df = df.sort_values("order")

    plt.figure(figsize=(6, 4.2))
    plt.bar(df[sev_col], df[count_col])
    plt.xlabel("Severity")
    plt.ylabel("Finding Count")
    plt.title("Severity Distribution of Detected Findings")
    plt.grid(axis="y", alpha=0.3)
    savefig("fig10_severity_distribution")


def main():
    fig1_prompt_security_drift_motivation()
    fig2_sdaf_conceptual_framework()
    fig3_securitydriftlab_architecture()
    fig4_dataset_generation_workflow()
    fig5_sdi_by_revision()
    fig6_metrics_by_revision()
    fig7_security_drift_lifecycle()
    fig8_model_comparison()
    fig9_cwe_distribution()
    fig10_severity_distribution()
    print("\nDone. Figures saved to:", FIG_DIR.resolve())


if __name__ == "__main__":
    main()
