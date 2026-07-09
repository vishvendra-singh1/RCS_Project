"""
RCS Database Module
====================
SQLite-backed storage for the Resilient Cloud Security Framework.

Four record types are supported, each with a different default
sensitivity classification:

    medical_records   → HIGH   (always ABE)
    financial_records → HIGH   (always ABE)
    hr_records        → MEDIUM (AES or ABE depending on exact score)
    documents         → LOW    (usually AES)

Each record can be stored in two states:
    - plaintext  : original data visible, not yet encrypted
    - encrypted  : AES-256-GCM or ABE ciphertext stored, plaintext wiped

The pipeline flow:
    1. User selects a record
    2. Sensitivity score computed from record's classification + threat level
    3. Record encrypted with AES or ABE based on score
    4. Encrypted blob stored back to DB (plaintext column wiped)
    5. Decryption retrieves the blob and recovers original data
"""

import sqlite3
import json
import os
from typing import Optional, Dict, List

DB_PATH = os.path.join(os.path.dirname(__file__), "rcs_data.db")

SENSITIVITY_MAP = {
    "HIGH":   0.85,
    "MEDIUM": 0.50,
    "LOW":    0.25,
}


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they don't exist and seed with sample data."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient     TEXT NOT NULL,
            age         INTEGER,
            diagnosis   TEXT,
            doctor      TEXT,
            notes       TEXT,
            sensitivity TEXT DEFAULT 'HIGH',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS financial_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account     TEXT NOT NULL,
            holder      TEXT,
            txn_type    TEXT,
            amount      REAL,
            description TEXT,
            sensitivity TEXT DEFAULT 'HIGH',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS hr_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            employee    TEXT NOT NULL,
            department  TEXT,
            salary      REAL,
            role        TEXT,
            performance TEXT,
            sensitivity TEXT DEFAULT 'MEDIUM',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            owner       TEXT,
            category    TEXT,
            content     TEXT,
            sensitivity TEXT DEFAULT 'LOW',
            encrypted   INTEGER DEFAULT 0,
            enc_scheme  TEXT,
            enc_blob    TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    _seed_data()


def _seed_data():
    """Insert sample records if tables are empty."""
    conn = get_connection()
    c = conn.cursor()

    if c.execute("SELECT COUNT(*) FROM medical_records").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO medical_records (patient, age, diagnosis, doctor, notes) VALUES (?,?,?,?,?)",
            [
                ("Arjun Sharma",  34, "Type 2 Diabetes",       "Dr. Mehta",  "Insulin prescribed, follow-up in 3 months"),
                ("Priya Nair",    28, "Hypertension",           "Dr. Kapoor", "Low sodium diet, 5mg amlodipine daily"),
                ("Ravi Patel",    52, "Coronary Artery Disease","Dr. Singh",  "Stent placed, cardiac rehab recommended"),
                ("Sneha Gupta",   45, "Hypothyroidism",         "Dr. Rao",    "Levothyroxine 50mcg, TSH recheck in 6 weeks"),
                ("Vikram Reddy",  61, "Chronic Kidney Disease", "Dr. Joshi",  "Stage 3 CKD, restrict protein intake"),
            ]
        )

    if c.execute("SELECT COUNT(*) FROM financial_records").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO financial_records (account, holder, txn_type, amount, description) VALUES (?,?,?,?,?)",
            [
                ("ACC-001-2024", "Rahul Verma",  "DEBIT",  45000.00,  "EMI payment — Home Loan"),
                ("ACC-002-2024", "Anjali Mehta", "CREDIT", 125000.00, "Monthly salary credit"),
                ("ACC-003-2024", "Suresh Kumar", "DEBIT",  8750.50,   "Insurance premium — LIC"),
                ("ACC-004-2024", "Meena Iyer",   "CREDIT", 50000.00,  "FD maturity amount"),
                ("ACC-005-2024", "Deepak Joshi", "DEBIT",  2300.00,   "Utility bill payment"),
            ]
        )

    if c.execute("SELECT COUNT(*) FROM hr_records").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO hr_records (employee, department, salary, role, performance) VALUES (?,?,?,?,?)",
            [
                ("Amit Singh",   "Engineering", 95000.00, "Senior Developer",    "Exceeds Expectations"),
                ("Kavya Pillai", "Data Science",88000.00, "ML Engineer",         "Meets Expectations"),
                ("Rohan Das",    "Finance",     72000.00, "Financial Analyst",   "Exceeds Expectations"),
                ("Pooja Tiwari", "HR",          65000.00, "HR Manager",          "Meets Expectations"),
                ("Nikhil Bose",  "Marketing",   60000.00, "Marketing Executive", "Below Expectations"),
            ]
        )

    if c.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO documents (title, owner, category, content, sensitivity) VALUES (?,?,?,?,?)",
            [
                ("Q1 2024 Sales Report",  "admin", "Finance",    "Total revenue: ₹12.4 Cr. Top region: South India. Growth vs Q1 2023: +18%.", "LOW"),
                ("Cloud Migration Plan",  "admin", "IT",         "Phase 1: Lift-and-shift by March. Phase 2: Re-architecture by June.",         "MEDIUM"),
                ("Board Meeting Minutes", "admin", "Management", "Budget approved ₹50L for AI initiatives. Headcount freeze until Q3.",          "HIGH"),
                ("Employee Handbook v3",  "hr",    "HR",         "Leave policy: 24 EL + 12 CL + 6 SL per year. WFH: 2 days/week max.",         "LOW"),
                ("Product Roadmap 2025",  "admin", "Product",    "H1: Launch mobile app. H2: Enterprise tier. AI features planned for Q4.",     "MEDIUM"),
            ]
        )

    conn.commit()
    conn.close()


def get_all_records(table: str) -> List[Dict]:
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"SELECT * FROM {table} ORDER BY id")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


def get_record(table: str, record_id: int) -> Optional[Dict]:
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_plaintext_summary(record: Dict, table: str) -> str:
    if table == "medical_records":
        return (f"Patient: {record['patient']} | Age: {record['age']} | "
                f"Diagnosis: {record['diagnosis']} | Doctor: {record['doctor']} | "
                f"Notes: {record['notes']}")
    elif table == "financial_records":
        return (f"Account: {record['account']} | Holder: {record['holder']} | "
                f"Type: {record['txn_type']} | Amount: ₹{record['amount']:,.2f} | "
                f"Description: {record['description']}")
    elif table == "hr_records":
        return (f"Employee: {record['employee']} | Dept: {record['department']} | "
                f"Salary: ₹{record['salary']:,.2f} | Role: {record['role']} | "
                f"Performance: {record['performance']}")
    elif table == "documents":
        return (f"Title: {record['title']} | Owner: {record['owner']} | "
                f"Category: {record['category']} | Content: {record['content']}")
    return str(record)


def encrypt_and_store(table: str, record_id: int, scheme: str, encrypted_blob) -> bool:
    conn = get_connection()
    c = conn.cursor()
    blob_str = json.dumps(encrypted_blob) if isinstance(encrypted_blob, dict) \
               else (encrypted_blob if isinstance(encrypted_blob, str) else encrypted_blob.hex())
    c.execute(
        f"UPDATE {table} SET encrypted=1, enc_scheme=?, enc_blob=? WHERE id=?",
        (scheme, blob_str, record_id)
    )
    conn.commit()
    conn.close()
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
        blob = bytes.fromhex(blob_str)
        return aes_decrypt(blob)
    elif scheme == "ABE":
        pkg = json.loads(blob_str)
        if user_attrs is None:
            return None
        return abe_decrypt(pkg, set(user_attrs))
    return None


def reset_record(table: str, record_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE {table} SET encrypted=0, enc_scheme=NULL, enc_blob=NULL WHERE id=?",
        (record_id,)
    )
    conn.commit()
    conn.close()