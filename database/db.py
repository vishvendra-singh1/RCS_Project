"""
RCS Database Module
====================
Supports two backends:
  - PostgreSQL (Supabase) when running on Streamlit Cloud
    (connection URL read from st.secrets["supabase"]["url"])
  - SQLite when running locally (fallback, zero config)

The same API is exposed regardless of backend.
"""

import json
import os
from typing import Optional, Dict, List

def _get_backend():
    try:
        import streamlit as st
        url = st.secrets["supabase"]["url"]
        return "postgres", url
    except Exception:
        return "sqlite", None

SENSITIVITY_MAP = {
    "HIGH":   0.85,
    "MEDIUM": 0.50,
    "LOW":    0.25,
}

SQLITE_DB_PATH = os.path.join(os.path.dirname(__file__), "rcs_data.db")


def _pg_conn(url: str):
    import psycopg2
    import psycopg2.extras
    return psycopg2.connect(url)


def _sqlite_conn():
    import sqlite3
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _execute(sql: str, params=(), fetch=None, commit=False):
    backend, url = _get_backend()

    if backend == "postgres":
        import psycopg2.extras
        conn = _pg_conn(url)
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        result = None
        if fetch == "all":
            result = [dict(r) for r in cur.fetchall()]
        elif fetch == "one":
            row = cur.fetchone()
            result = dict(row) if row else None
        if commit:
            conn.commit()
        conn.close()
        return result
    else:
        conn = _sqlite_conn()
        cur  = conn.cursor()
        cur.execute(sql, params)
        result = None
        if fetch == "all":
            result = [dict(r) for r in cur.fetchall()]
        elif fetch == "one":
            row = cur.fetchone()
            result = dict(row) if row else None
        if commit:
            conn.commit()
        conn.close()
        return result


def init_db():
    backend, url = _get_backend()

    if backend == "postgres":
        pk = "SERIAL PRIMARY KEY"
        ts = "TIMESTAMP DEFAULT NOW()"
    else:
        pk = "INTEGER PRIMARY KEY AUTOINCREMENT"
        ts = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"

    tables = [
        f"""CREATE TABLE IF NOT EXISTS medical_records (
            id          {pk},
            patient     TEXT NOT NULL,
            age         INTEGER,
            diagnosis   TEXT,
            doctor      TEXT,
            notes       TEXT,
            sensitivity TEXT DEFAULT 'HIGH',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  {ts}
        )""",
        f"""CREATE TABLE IF NOT EXISTS financial_records (
            id          {pk},
            account     TEXT NOT NULL,
            holder      TEXT,
            txn_type    TEXT,
            amount      REAL,
            description TEXT,
            sensitivity TEXT DEFAULT 'HIGH',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  {ts}
        )""",
        f"""CREATE TABLE IF NOT EXISTS hr_records (
            id          {pk},
            employee    TEXT NOT NULL,
            department  TEXT,
            salary      REAL,
            role        TEXT,
            performance TEXT,
            sensitivity TEXT DEFAULT 'MEDIUM',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  {ts}
        )""",
        f"""CREATE TABLE IF NOT EXISTS documents (
            id          {pk},
            title       TEXT NOT NULL,
            owner       TEXT,
            category    TEXT,
            content     TEXT,
            sensitivity TEXT DEFAULT 'LOW',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  {ts}
        )""",
    ]

    for sql in tables:
        _execute(sql, commit=True)

    _seed_data()


def _seed_data():
    def count(table):
        row = _execute(f"SELECT COUNT(*) as c FROM {table}", fetch="one")
        return row["c"] if row else 0

    backend, _ = _get_backend()
    ph = "%s" if backend == "postgres" else "?"

    if count("medical_records") == 0:
        for row in [
            ("Arjun Sharma",  34, "Type 2 Diabetes",        "Dr. Mehta",  "Insulin prescribed, follow-up in 3 months"),
            ("Priya Nair",    28, "Hypertension",            "Dr. Kapoor", "Low sodium diet, 5mg amlodipine daily"),
            ("Ravi Patel",    52, "Coronary Artery Disease", "Dr. Singh",  "Stent placed, cardiac rehab recommended"),
            ("Sneha Gupta",   45, "Hypothyroidism",          "Dr. Rao",    "Levothyroxine 50mcg, TSH recheck in 6 weeks"),
            ("Vikram Reddy",  61, "Chronic Kidney Disease",  "Dr. Joshi",  "Stage 3 CKD, restrict protein intake"),
        ]:
            _execute(f"INSERT INTO medical_records (patient,age,diagnosis,doctor,notes) VALUES ({ph},{ph},{ph},{ph},{ph})", row, commit=True)

    if count("financial_records") == 0:
        for row in [
            ("ACC-001-2024", "Rahul Verma",  "DEBIT",  45000.00,  "EMI payment - Home Loan"),
            ("ACC-002-2024", "Anjali Mehta", "CREDIT", 125000.00, "Monthly salary credit"),
            ("ACC-003-2024", "Suresh Kumar", "DEBIT",  8750.50,   "Insurance premium - LIC"),
            ("ACC-004-2024", "Meena Iyer",   "CREDIT", 50000.00,  "FD maturity amount"),
            ("ACC-005-2024", "Deepak Joshi", "DEBIT",  2300.00,   "Utility bill payment"),
        ]:
            _execute(f"INSERT INTO financial_records (account,holder,txn_type,amount,description) VALUES ({ph},{ph},{ph},{ph},{ph})", row, commit=True)

    if count("hr_records") == 0:
        for row in [
            ("Amit Singh",   "Engineering", 95000.00, "Senior Developer",    "Exceeds Expectations"),
            ("Kavya Pillai", "Data Science",88000.00, "ML Engineer",         "Meets Expectations"),
            ("Rohan Das",    "Finance",     72000.00, "Financial Analyst",   "Exceeds Expectations"),
            ("Pooja Tiwari", "HR",          65000.00, "HR Manager",          "Meets Expectations"),
            ("Nikhil Bose",  "Marketing",   60000.00, "Marketing Executive", "Below Expectations"),
        ]:
            _execute(f"INSERT INTO hr_records (employee,department,salary,role,performance) VALUES ({ph},{ph},{ph},{ph},{ph})", row, commit=True)

    if count("documents") == 0:
        for row in [
            ("Q1 2024 Sales Report",  "admin","Finance",   "Total revenue: Rs12.4 Cr. Top region: South India. Growth +18%.","LOW"),
            ("Cloud Migration Plan",  "admin","IT",        "Phase 1: Lift-and-shift by March. Phase 2: Re-architecture June.","MEDIUM"),
            ("Board Meeting Minutes", "admin","Management","Budget approved Rs50L for AI initiatives. Headcount freeze Q3.",  "HIGH"),
            ("Employee Handbook v3",  "hr",   "HR",        "Leave: 24 EL + 12 CL + 6 SL per year. WFH: 2 days/week max.",   "LOW"),
            ("Product Roadmap 2025",  "admin","Product",   "H1: Mobile app. H2: Enterprise tier. AI features Q4.",           "MEDIUM"),
        ]:
            _execute(f"INSERT INTO documents (title,owner,category,content,sensitivity) VALUES ({ph},{ph},{ph},{ph},{ph})", row, commit=True)


def get_all_records(table: str) -> List[Dict]:
    return _execute(f"SELECT * FROM {table} ORDER BY id", fetch="all") or []


def get_record(table: str, record_id: int) -> Optional[Dict]:
    backend, _ = _get_backend()
    ph = "%s" if backend == "postgres" else "?"
    return _execute(f"SELECT * FROM {table} WHERE id = {ph}", (record_id,), fetch="one")


def get_plaintext_summary(record: Dict, table: str) -> str:
    if table == "medical_records":
        return (f"Patient: {record['patient']} | Age: {record['age']} | "
                f"Diagnosis: {record['diagnosis']} | Doctor: {record['doctor']} | "
                f"Notes: {record['notes']}")
    elif table == "financial_records":
        return (f"Account: {record['account']} | Holder: {record['holder']} | "
                f"Type: {record['txn_type']} | Amount: Rs{record['amount']:,.2f} | "
                f"Description: {record['description']}")
    elif table == "hr_records":
        return (f"Employee: {record['employee']} | Dept: {record['department']} | "
                f"Salary: Rs{record['salary']:,.2f} | Role: {record['role']} | "
                f"Performance: {record['performance']}")
    elif table == "documents":
        return (f"Title: {record['title']} | Owner: {record['owner']} | "
                f"Category: {record['category']} | Content: {record['content']}")
    return str(record)


def encrypt_and_store(table: str, record_id: int, scheme: str, encrypted_blob) -> bool:
    backend, _ = _get_backend()
    ph = "%s" if backend == "postgres" else "?"
    blob_str = json.dumps(encrypted_blob) if isinstance(encrypted_blob, dict) \
               else (encrypted_blob if isinstance(encrypted_blob, str) else encrypted_blob.hex())
    _execute(
        f"UPDATE {table} SET encrypted=1, enc_scheme={ph}, enc_blob={ph} WHERE id={ph}",
        (scheme, blob_str, record_id), commit=True
    )
    return True


def decrypt_record(table: str, record_id: int, user_attrs=None) -> Optional[str]:
    from encryption.aes_encrypt import aes_decrypt
    from encryption.abe import abe_decrypt

    record = get_record(table, record_id)
    if not record or not record["encrypted"]:
        return None

    scheme   = record["enc_scheme"]
    blob_str = record["enc_blob"]

    if scheme == "AES-256-GCM":
        return aes_decrypt(bytes.fromhex(blob_str))
    elif scheme == "ABE":
        pkg = json.loads(blob_str)
        if user_attrs is None:
            return None
        return abe_decrypt(pkg, set(user_attrs))
    return None


def reset_record(table: str, record_id: int):
    backend, _ = _get_backend()
    ph = "%s" if backend == "postgres" else "?"
    _execute(
        f"UPDATE {table} SET encrypted=0, enc_scheme=NULL, enc_blob=NULL WHERE id={ph}",
        (record_id,), commit=True
    )