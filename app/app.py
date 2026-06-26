import sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

import streamlit as st
import pandas as pd

from securitydriftlab.db import (
    init_db,
    fetch_df,
    insert_prompt,
    insert_output,
)
from securitydriftlab.seed_data import seed_tasks
from securitydriftlab.prompt_generator import generate_prompt
from securitydriftlab.llm_client import has_api_key, generate_with_openai
from securitydriftlab.scanner import save_output_code, scan_file
from securitydriftlab.sdi import compute_all_sdi
from securitydriftlab.exports import export_all

st.set_page_config(page_title="SecurityDriftLab-Auto", layout="wide")
init_db()

st.title("SecurityDriftLab-Auto")
st.caption("Automated framework for measuring Security Drift in prompt evolution.")

with st.sidebar:
    st.header("Setup")
    col_seed1, col_seed2 = st.columns(2)
    with col_seed1:
        if st.button("Seed 100 Tasks"):
            seed_tasks(multiplier=2)
            st.success("Seeded 100 tasks.")
    with col_seed2:
        if st.button("Seed 200 Tasks"):
            seed_tasks(multiplier=4)
            st.success("Seeded 200 tasks.")

    st.write("API key detected:", "YES" if has_api_key() else "NO - manual mode enabled")
    model = st.text_input("Default model name", value=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"))
    model_list_text = st.text_area(
        "Models for full pipeline, one per line",
        value="gpt-4.1-mini\ngpt-5.4-mini\ngpt-5.4-nano",
        height=90
    )
    model_list = [m.strip() for m in model_list_text.splitlines() if m.strip()]

    st.divider()
    st.subheader("Scanner Options")
    enable_bandit = st.checkbox("Run Bandit", value=True)
    enable_semgrep = st.checkbox("Run Semgrep", value=False)
    enable_heuristic = st.checkbox("Run built-in heuristic scanner", value=True)

    st.divider()
    st.subheader("Full Run Options")
    max_tasks = st.number_input("Max tasks to run", min_value=1, max_value=500, value=50)
    max_revisions = st.selectbox("Revisions per task", [1, 2, 3, 4], index=3)

tabs = st.tabs([
    "One-Button Pipeline",
    "Tasks & Generation",
    "Manual Output",
    "Scan & SDI",
    "Dashboard",
    "Export"
])

with tabs[0]:
    st.subheader("One-Button Pipeline")

    st.write(
        "This runs the complete automatic workflow for the selected number of tasks: "
        "generate prompt revisions, call OpenAI if an API key is configured, save outputs, "
        "scan generated code, compute SDI, and export CSV tables."
    )

    st.warning(
        "If no OpenAI API key is configured, this button will still generate and save prompts, "
        "but it cannot generate code outputs automatically. You can paste outputs manually in the Manual Output tab."
    )

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        run_prompts = st.checkbox("Generate/save prompts", value=True)
    with col_b:
        run_llm = st.checkbox("Call OpenAI for outputs", value=has_api_key())
    with col_c:
        run_scans = st.checkbox("Scan outputs and compute SDI", value=True)

    if st.button("Run Full Pipeline", type="primary"):
        tasks = fetch_df("SELECT * FROM tasks ORDER BY task_id")
        if tasks.empty:
            seed_tasks(multiplier=4)
            tasks = fetch_df("SELECT * FROM tasks ORDER BY task_id")

        selected_tasks = tasks.head(int(max_tasks))
        progress_total = len(selected_tasks) * int(max_revisions)
        progress = st.progress(0)
        status = st.empty()

        saved_prompts = 0
        saved_outputs = 0
        scanned_outputs = 0
        errors = []

        step = 0

        for _, task_row in selected_tasks.iterrows():
            task = task_row.to_dict()
            task_id = task["task_id"]

            for revision in range(1, int(max_revisions) + 1):
                step += 1
                status.write(f"Processing {task_id} revision {revision}...")
                prompt = generate_prompt(task, revision)

                if run_prompts:
                    try:
                        insert_prompt(task_id, model, revision, prompt)
                        saved_prompts += 1
                    except Exception as e:
                        errors.append(f"Prompt save error {task_id} r{revision}: {e}")

                if run_llm:
                    try:
                        output = generate_with_openai(prompt, model=model)
                        file_path = save_output_code(task_id, model, revision, output)
                        insert_output(task_id, model, revision, output, file_path)
                        saved_outputs += 1

                        if run_scans:
                            scan_file(
                                task_id,
                                model,
                                revision,
                                file_path,
                                enable_bandit=enable_bandit,
                                enable_semgrep=enable_semgrep,
                                enable_heuristic=enable_heuristic,
                            )
                            scanned_outputs += 1
                    except Exception as e:
                        errors.append(f"LLM/scan error {task_id} r{revision}: {e}")

                progress.progress(min(step / progress_total, 1.0))

        if run_scans:
            try:
                # Also scan any existing outputs, including manually pasted outputs.
                outputs = fetch_df("SELECT * FROM outputs ORDER BY created_at DESC")
                for _, row in outputs.iterrows():
                    scan_file(
                        row["task_id"],
                        row["model"],
                        int(row["revision"]),
                        row["file_path"],
                        enable_bandit=enable_bandit,
                        enable_semgrep=enable_semgrep,
                        enable_heuristic=enable_heuristic,
                    )
                sdi_rows = compute_all_sdi()
                export_paths = export_all()
            except Exception as e:
                errors.append(f"Scan/SDI/export error: {e}")
                sdi_rows = []
                export_paths = []
        else:
            sdi_rows = []
            export_paths = export_all()

        st.success(
            f"Pipeline complete. Saved prompts: {saved_prompts}. "
            f"Saved outputs: {saved_outputs}. Scanned outputs: {scanned_outputs}. "
            f"SDI records computed: {len(sdi_rows)}."
        )

        if export_paths:
            st.write("Exported files:")
            for p in export_paths:
                st.code(p)

        if errors:
            st.error("Some steps produced errors.")
            for err in errors[:20]:
                st.write(err)

with tabs[1]:
    st.subheader("Tasks")
    tasks = fetch_df("SELECT * FROM tasks ORDER BY task_id")
    st.dataframe(tasks, use_container_width=True)

    if not tasks.empty:
        task_id = st.selectbox("Select task", tasks["task_id"].tolist())
        task = tasks[tasks["task_id"] == task_id].iloc[0].to_dict()
        revision = st.selectbox("Revision", [1, 2, 3, 4])
        prompt = generate_prompt(task, revision)
        st.text_area("Generated Prompt", prompt, height=280)

        if st.button("Save Prompt"):
            insert_prompt(task_id, model, revision, prompt)
            st.success("Prompt saved.")

        if st.button("Run OpenAI and Save Output"):
            try:
                output = generate_with_openai(prompt, model=model)
                file_path = save_output_code(task_id, model, revision, output)
                insert_prompt(task_id, model, revision, prompt)
                insert_output(task_id, model, revision, output, file_path)
                st.success(f"Output saved to {file_path}")
                st.code(output[:4000])
            except Exception as e:
                st.error(str(e))

with tabs[2]:
    st.subheader("Paste Manual Output")
    tasks = fetch_df("SELECT * FROM tasks ORDER BY task_id")
    if not tasks.empty:
        task_id = st.selectbox("Task", tasks["task_id"].tolist(), key="manual_task")
        model_manual = st.text_input("Model", value=model, key="manual_model")
        revision_manual = st.selectbox("Revision", [1, 2, 3, 4], key="manual_revision")
        output_text = st.text_area("Paste generated code/output", height=350)

        if st.button("Save Manual Output"):
            file_path = save_output_code(task_id, model_manual, revision_manual, output_text)
            insert_output(task_id, model_manual, revision_manual, output_text, file_path)
            st.success(f"Saved to {file_path}")

with tabs[3]:
    st.subheader("Scan Outputs and Compute SDI")
    outputs = fetch_df("SELECT * FROM outputs ORDER BY created_at DESC")
    st.dataframe(
        outputs[["task_id", "model", "revision", "file_path", "created_at"]] if not outputs.empty else outputs,
        use_container_width=True
    )

    if st.button("Scan All Saved Outputs"):
        count = 0
        for _, row in outputs.iterrows():
            scan_file(
                row["task_id"],
                row["model"],
                int(row["revision"]),
                row["file_path"],
                enable_bandit,
                enable_semgrep,
                enable_heuristic,
            )
            count += 1
        st.success(f"Scanned {count} outputs.")

    if st.button("Compute All SDI"):
        rows = compute_all_sdi()
        st.success(f"Computed {len(rows)} SDI records.")

    if st.button("Scan All Outputs + Compute SDI + Export", type="primary"):
        count = 0
        for _, row in outputs.iterrows():
            scan_file(
                row["task_id"],
                row["model"],
                int(row["revision"]),
                row["file_path"],
                enable_bandit,
                enable_semgrep,
                enable_heuristic,
            )
            count += 1
        rows = compute_all_sdi()
        paths = export_all()
        st.success(f"Scanned {count} outputs, computed {len(rows)} SDI records, and exported {len(paths)} files.")
        for p in paths:
            st.code(p)

    scans = fetch_df("SELECT * FROM scans ORDER BY created_at DESC LIMIT 200")
    st.subheader("Recent Findings")
    st.dataframe(scans, use_container_width=True)

with tabs[4]:
    st.subheader("Dashboard")
    sdi = fetch_df("SELECT * FROM sdi")

    if sdi.empty:
        st.info("No SDI data yet. Scan outputs and compute SDI first.")
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("SDI Records", len(sdi))
        col2.metric("Avg SDI", round(sdi["sdi"].mean(), 2))
        col3.metric("Max SDI", round(sdi["sdi"].max(), 2))

        st.subheader("SDI by Revision")
        st.bar_chart(sdi.groupby("revision")["sdi"].mean())

        joined = fetch_df("SELECT sdi.*, tasks.category FROM sdi JOIN tasks ON sdi.task_id=tasks.task_id")
        st.subheader("SDI by Category")
        st.bar_chart(joined.groupby("category")["sdi"].mean())

        st.subheader("SDI by Model")
        st.bar_chart(sdi.groupby("model")["sdi"].mean())

        st.dataframe(joined, use_container_width=True)

with tabs[5]:
    st.subheader("Export Data")
    if st.button("Export CSV Tables"):
        paths = export_all()
        st.success("Export complete.")
        for p in paths:
            st.code(p)
