import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path("data/securitydriftlab.sqlite3")

def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        category TEXT,
        title TEXT,
        description TEXT,
        acceptance_criteria TEXT,
        language TEXT DEFAULT 'python'
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS prompts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT,
        model TEXT,
        revision INTEGER,
        prompt_text TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS outputs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT,
        model TEXT,
        revision INTEGER,
        output_text TEXT,
        file_path TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT,
        model TEXT,
        revision INTEGER,
        scanner TEXT,
        finding_id TEXT,
        cwe TEXT,
        severity TEXT,
        message TEXT,
        file_path TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS sdi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT,
        model TEXT,
        revision INTEGER,
        new_vulns INTEGER,
        removed_vulns INTEGER,
        severity_delta REAL,
        regressions INTEGER,
        improvements INTEGER,
        sdi REAL,
        swsdi REAL,
        srr REAL,
        vc INTEGER,
        prev_vulns INTEGER,
        curr_vulns INTEGER,
        new_low INTEGER,
        new_medium INTEGER,
        new_high INTEGER,
        new_critical INTEGER,
        removed_low INTEGER,
        removed_medium INTEGER,
        removed_high INTEGER,
        removed_critical INTEGER,
        created_at TEXT
    )
    """)

    existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(sdi)").fetchall()}
    new_cols = {
        "swsdi": "REAL",
        "srr": "REAL",
        "vc": "INTEGER",
        "prev_vulns": "INTEGER",
        "curr_vulns": "INTEGER",
        "new_low": "INTEGER",
        "new_medium": "INTEGER",
        "new_high": "INTEGER",
        "new_critical": "INTEGER",
        "removed_low": "INTEGER",
        "removed_medium": "INTEGER",
        "removed_high": "INTEGER",
        "removed_critical": "INTEGER",
    }

    for col, col_type in new_cols.items():
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE sdi ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()

def upsert_task(task):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO tasks (task_id, category, title, description, acceptance_criteria, language)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        task["task_id"],
        task["category"],
        task["title"],
        task["description"],
        task["acceptance_criteria"],
        task.get("language", "python"),
    ))
    conn.commit()
    conn.close()

def insert_prompt(task_id, model, revision, prompt_text):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO prompts (task_id, model, revision, prompt_text, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (task_id, model, revision, prompt_text, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def insert_output(task_id, model, revision, output_text, file_path):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO outputs (task_id, model, revision, output_text, file_path, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (task_id, model, revision, output_text, file_path, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def clear_scans_for(task_id, model, revision):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM scans WHERE task_id=? AND model=? AND revision=?",
        (task_id, model, revision),
    )
    conn.commit()
    conn.close()

def insert_scan(task_id, model, revision, scanner, finding_id, cwe, severity, message, file_path):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO scans (task_id, model, revision, scanner, finding_id, cwe, severity, message, file_path, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        task_id,
        model,
        revision,
        scanner,
        finding_id,
        cwe,
        severity,
        message,
        file_path,
        datetime.utcnow().isoformat(),
    ))
    conn.commit()
    conn.close()

def fetch_df(query):
    import pandas as pd
    conn = get_conn()
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df
