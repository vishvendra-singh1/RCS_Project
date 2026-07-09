import numpy as np
import streamlit as st
import time
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import random
import pandas as pd

from acl.rbac import rbac
from acl.abac import abac
from encryption.aes_encrypt import aes_encrypt, aes_encrypt_for_storage
from encryption.abe import abe_encrypt, abe_decrypt
from encryption.sensitivity import sensitivity
from anomaly.train_rf import train_model, evaluate_model
from anomaly.detect import detect_anomaly
from database.db import (init_db, get_all_records, get_record,
                         get_plaintext_summary, encrypt_and_store,
                         decrypt_record, reset_record, SENSITIVITY_MAP)

# ---- Train the ML model once at app startup ----
@st.cache_resource
def load_model():
    return train_model()

# ---- Initialize database once ----
@st.cache_resource
def setup_db():
    init_db()
    return True

# ---- Page config ----
st.set_page_config(page_title="RCS — Resilient Cloud Security", layout="wide")
st.title("🔐 Resilient Cloud Security (RCS) Framework")
st.markdown("Three-layer cloud security: **RBAC/ABAC Access Control → Sensitivity-Based Encryption → ML Anomaly Detection**")
st.divider()

model = load_model()
setup_db()

# ====================== TABS ======================
tab1, tab2, tab3, tab4 = st.tabs(["🔬 Single Request Pipeline", "📊 Simulation Dashboard", "🧠 ML Evaluation", "🗄️ Database Explorer"])


# ==========================================
# TAB 1 — SINGLE REQUEST PIPELINE
# ==========================================
with tab1:
    st.sidebar.header("👤 Simulate a Request")
    role       = st.sidebar.selectbox("User Role", ["admin", "user"])
    location   = st.sidebar.selectbox("Location", ["India", "US", "UK"])
    time_val   = st.sidebar.slider("Access Time (Hour)", 0, 23, 12)
    data       = st.sidebar.text_input("Data to Encrypt", "Confidential Cloud Data")
    conf       = st.sidebar.slider("Data Confidentiality (0–1)", 0.0, 1.0, 0.7)
    threat     = st.sidebar.slider("Threat Score (0–1)", 0.0, 1.0, 0.5)
    run        = st.sidebar.button("▶ Run Security Pipeline", type="primary")

    if not run:
        st.info("Configure a request in the sidebar and click **Run Security Pipeline** to simulate all three security layers.")
    else:
        # --- LAYER 1 ---
        st.header("Layer 1 — Access Control (RBAC + ABAC)")
        col1, col2 = st.columns(2)
        env = {"location": location, "time": time_val}
        with col1:
            rbac_ok = rbac(role, "read")
            if rbac_ok:
                st.success(f"✅ RBAC passed — role `{role}` has read permission")
            else:
                st.error(f"❌ RBAC denied — role `{role}` does not have read permission")
        with col2:
            abac_ok = abac(env)
            if abac_ok:
                st.success(f"✅ ABAC passed — location `{location}`, time `{time_val}:00` is within policy")
            else:
                st.error(f"❌ ABAC denied — location `{location}` or time `{time_val}:00` violates policy")

        if not rbac_ok or not abac_ok:
            st.error("🚫 Request blocked at access control layer. Pipeline stopped.")
        else:
            st.success("✅ Access granted — proceeding to encryption layer")
            st.divider()

            # --- LAYER 2 ---
            st.header("Layer 2 — Sensitivity-Based Encryption (AES-256-GCM / ABE)")
            s = sensitivity(conf, 1, threat)
            st.metric("Computed Sensitivity Score", f"{s:.4f}", help="Threshold: > 0.6 → ABE, ≤ 0.6 → AES")

            col1, col2 = st.columns(2)
            with col1:
                aes_lats = []
                for _ in range(10):
                    t0 = time.perf_counter()
                    aes_output = aes_encrypt(data)
                    aes_lats.append((time.perf_counter() - t0) * 1000)
                st.metric("⚡ AES-256-GCM Avg Latency", f"{np.mean(aes_lats):.4f} ms")

            with col2:
                policy = {f"role:{role}", "region:india"}
                abe_lats = []
                abe_pkg = None
                for _ in range(10):
                    t0 = time.perf_counter()
                    abe_pkg = abe_encrypt(data, policy, policy)
                    abe_lats.append((time.perf_counter() - t0) * 1000)
                st.metric("🔐 ABE (SSS+AES-GCM) Avg Latency", f"{np.mean(abe_lats):.4f} ms")

            if s > 0.6:
                chosen = "ABE"
                st.warning(f"🔐 Sensitivity {s:.4f} > 0.6 → **ABE** selected (policy: `{policy}`)")
                encrypted_output = abe_pkg
                decrypted = abe_decrypt(abe_pkg, policy)
                st.success(f"✅ ABE decryption verified: `{decrypted}`")
            else:
                chosen = "AES"
                st.info(f"⚡ Sensitivity {s:.4f} ≤ 0.6 → **AES-256-GCM** selected")
                encrypted_output = aes_output

            with st.expander("📦 View encrypted output"):
                if chosen == "ABE":
                    st.json({k: v for k, v in encrypted_output.items() if k != "shares"})
                    st.caption("Shares omitted from display (contain per-attribute masked key material)")
                else:
                    st.code(str(encrypted_output), language="text")

            fig, ax = plt.subplots(figsize=(7, 3))
            ax.plot(aes_lats, marker='o', label="AES-256-GCM", color="#4C72B0")
            ax.plot(abe_lats, marker='x', label="ABE (SSS+AES-GCM)", color="#DD8452")
            ax.set_title("Encryption Latency — 10 runs")
            ax.set_xlabel("Run")
            ax.set_ylabel("Latency (ms)")
            ax.legend()
            ax.grid(True)
            st.pyplot(fig)
            st.divider()

            # --- LAYER 3 ---
            st.header("Layer 3 — Anomaly Detection (Random Forest)")
            entropy = s
            rate    = time_val * 4.0 + random.uniform(0, 5)
            volume  = conf * 500

            col1, col2, col3 = st.columns(3)
            col1.metric("Entropy (sensitivity)", f"{entropy:.4f}")
            col2.metric("Rate (req proxy)", f"{rate:.2f}")
            col3.metric("Volume (data size)", f"{volume:.1f}")

            is_anomaly = detect_anomaly(model, entropy, rate, volume)
            if is_anomaly:
                st.error("⚠️ **Anomaly Detected** — this request's access pattern was flagged as potentially malicious.")
            else:
                st.success("✅ **Normal Access** — the Random Forest classifier found no anomaly.")

            st.divider()

            # --- SUMMARY ---
            st.header("📊 Pipeline Summary")
            c = st.columns(4)
            c[0].metric("Access Control", "✅ Passed")
            c[1].metric("Encryption Used", chosen)
            c[2].metric("Sensitivity Score", f"{s:.4f}")
            c[3].metric("Anomaly", "⚠️ Yes" if is_anomaly else "✅ No")

            st.divider()

            # --- ABE POLICY EXPLORER ---
            st.header("🔑 ABE Policy Explorer — k-of-n Threshold Demo")
            st.markdown(
                "Demonstrate how **Shamir's Secret Sharing** enables fine-grained, "
                "threshold-based access control. Set a policy with multiple attributes "
                "and choose how many are required to decrypt. Try different combinations "
                "to see the cryptographic enforcement in action."
            )

            st.subheader("1. Define Policy Attributes")
            attr_input = st.text_input(
                "Policy attributes (comma-separated)",
                value="doctor_A, doctor_B, doctor_C",
                help="These are the attributes that form the encryption policy."
            )
            policy_attrs = [a.strip() for a in attr_input.split(",") if a.strip()]

            if len(policy_attrs) < 2:
                st.warning("Please enter at least 2 attributes.")
            else:
                n = len(policy_attrs)

                st.subheader("2. Set the Threshold (k of n)")
                k = st.slider(
                    f"How many attributes are required to decrypt? (out of {n})",
                    min_value=1, max_value=n, value=min(2, n),
                    help="k-of-n: any k attributes from the policy can reconstruct the key."
                )
                st.info(
                    f"Policy: any **{k} of {n}** attributes required — "
                    f"{'AND policy (all required)' if k == n else f'threshold policy ({k}-of-{n})'}"
                )

                abe_data = st.text_input(
                    "Data to encrypt under this policy",
                    value="Top Secret Medical Record",
                    key="abe_explorer_data"
                )

                if st.button("🔐 Encrypt with ABE Policy", key="abe_encrypt_btn"):
                    policy_set = set(policy_attrs)
                    pkg = abe_encrypt(abe_data, policy_set, policy_set, threshold=k)
                    st.session_state["abe_pkg"]    = pkg
                    st.session_state["abe_policy"] = policy_attrs
                    st.session_state["abe_k"]      = k
                    st.session_state["abe_data"]   = abe_data
                    st.success(f"✅ Data encrypted under policy: `{policy_attrs}` with threshold k={k}")
                    with st.expander("📦 View ciphertext package"):
                        st.json({kk: vv for kk, vv in pkg.items() if kk != "shares"})
                        st.caption("Shares omitted (contain per-attribute masked key material)")

                if "abe_pkg" in st.session_state:
                    st.subheader("3. Try to Decrypt")
                    st.markdown(
                        f"Select which attributes you **hold** as the decryptor. "
                        f"You need at least **{st.session_state['abe_k']}** matching attribute(s) to succeed."
                    )

                    held_attrs = st.multiselect(
                        "Your attributes (select what you hold):",
                        options=st.session_state["abe_policy"],
                        default=st.session_state["abe_policy"][:st.session_state["abe_k"]],
                        key="abe_held_attrs"
                    )

                    if st.button("🔓 Attempt Decryption", key="abe_decrypt_btn"):
                        matching = [a for a in held_attrs if a in st.session_state["abe_policy"]]
                        result   = abe_decrypt(st.session_state["abe_pkg"], set(held_attrs))

                        dec_cols = st.columns(3)
                        dec_cols[0].metric("Attributes held",       len(held_attrs))
                        dec_cols[1].metric("Threshold required",    st.session_state["abe_k"])
                        dec_cols[2].metric("Matching policy attrs", len(matching))

                        if result is not None:
                            st.success(f"✅ **Decryption successful!** Recovered: `{result}`")
                            st.balloons()
                        else:
                            st.error(
                                f"❌ **Decryption failed.** "
                                f"You hold {len(matching)} matching attribute(s) but need "
                                f"{st.session_state['abe_k']}. The AES-GCM authentication "
                                f"tag verification failed — wrong key reconstructed."
                            )

                    st.subheader("4. Scenario Comparison")
                    st.markdown("All possible attribute combinations and whether they can decrypt:")
                    from itertools import combinations
                    rows = []
                    pol  = st.session_state["abe_policy"]
                    kk   = st.session_state["abe_k"]
                    for r in range(1, len(pol) + 1):
                        for combo in combinations(pol, r):
                            res = abe_decrypt(st.session_state["abe_pkg"], set(combo))
                            rows.append({
                                "Attributes held":   ", ".join(combo),
                                "Count":             len(combo),
                                "Meets threshold":   "✅ Yes" if len(combo) >= kk else "❌ No",
                                "Decryption result": "✅ Success" if res is not None else "❌ Failed"
                            })
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)


# ==========================================
# TAB 2 — SIMULATION DASHBOARD
# ==========================================
with tab2:
    st.header("📊 500-Request Simulation Dashboard")
    st.markdown("Runs the full RCS pipeline across 500 simulated cloud access requests — live.")

    TOTAL = 500
    run_sim = st.button("▶ Run 500-Request Simulation", type="primary")

    if not run_sim:
        st.info("Click **Run 500-Request Simulation** to start. The simulation runs all 500 requests live with a progress bar.")
    else:
        progress_bar  = st.progress(0, text="Starting simulation...")
        metric_cols   = st.columns(5)
        m_processed   = metric_cols[0].empty()
        m_denied      = metric_cols[1].empty()
        m_aes         = metric_cols[2].empty()
        m_abe         = metric_cols[3].empty()
        m_anomaly     = metric_cols[4].empty()

        denied_count  = 0
        aes_count     = 0
        abe_count     = 0
        anomaly_count = 0
        aes_latencies = []
        abe_latencies = []
        log_rows      = []

        sim_start = time.perf_counter()

        for i in range(TOTAL):
            role_s   = random.choice(["admin", "user"])
            loc_s    = random.choice(["India", "US", "UK"])
            time_s   = random.randint(0, 23)
            env_s    = {"location": loc_s, "time": time_s}
            conf_s   = random.random()
            threat_s = random.random()

            if not rbac(role_s, "read") or not abac(env_s):
                denied_count += 1
                log_rows.append({
                    "req": i + 1, "role": role_s, "location": loc_s,
                    "status": "DENIED", "encryption": "—",
                    "anomaly": "—", "latency_ms": 0
                })
                if (i + 1) % 25 == 0 or i == 0:
                    progress_bar.progress((i + 1) / TOTAL, text=f"Processing request {i+1}/{TOTAL}...")
                    m_processed.metric("Processed", aes_count + abe_count)
                    m_denied.metric("Denied", denied_count)
                    m_aes.metric("AES Applied", aes_count)
                    m_abe.metric("ABE Applied", abe_count)
                    m_anomaly.metric("Anomalies", anomaly_count)
                continue

            s_score  = sensitivity(conf_s, 1, threat_s)
            policy_s = {f"role:{role_s}", "region:india"}

            if s_score > 0.6:
                t0 = time.perf_counter()
                abe_encrypt("Confidential Data", policy_s, policy_s)
                lat = (time.perf_counter() - t0) * 1000
                abe_latencies.append(lat)
                abe_count += 1
                enc_used = "ABE"
            else:
                t0 = time.perf_counter()
                aes_encrypt("Confidential Data")
                lat = (time.perf_counter() - t0) * 1000
                aes_latencies.append(lat)
                aes_count += 1
                enc_used = "AES"

            entropy_s = s_score
            rate_s    = (i % 100) + random.uniform(0, 5)
            volume_s  = random.uniform(50, 500)
            anom      = detect_anomaly(model, entropy_s, rate_s, volume_s)
            if anom:
                anomaly_count += 1

            log_rows.append({
                "req": i + 1, "role": role_s, "location": loc_s,
                "status": "OK", "encryption": enc_used,
                "anomaly": "⚠️ Yes" if anom else "✅ No",
                "latency_ms": round(lat, 3)
            })

            if (i + 1) % 25 == 0 or i == 0:
                progress_bar.progress((i + 1) / TOTAL, text=f"Processing request {i+1}/{TOTAL}...")
                m_processed.metric("Processed", aes_count + abe_count)
                m_denied.metric("Denied", denied_count)
                m_aes.metric("AES Applied", aes_count)
                m_abe.metric("ABE Applied", abe_count)
                m_anomaly.metric("Anomalies", anomaly_count)

        sim_end    = time.perf_counter()
        total_time = sim_end - sim_start
        processed  = aes_count + abe_count
        throughput = processed / total_time

        progress_bar.progress(1.0, text="✅ Simulation complete!")

        st.divider()
        st.subheader("📋 Final Summary")
        fc = st.columns(5)
        fc[0].metric("Total Requests", TOTAL)
        fc[1].metric("Processed", processed)
        fc[2].metric("Denied", denied_count)
        fc[3].metric("Anomalies Detected", anomaly_count)
        fc[4].metric("Throughput", f"{throughput:.1f} req/s")

        lc = st.columns(4)
        lc[0].metric("AES Applied", aes_count)
        lc[1].metric("ABE Applied", abe_count)
        if aes_latencies:
            lc[2].metric("AES Avg Latency", f"{np.mean(aes_latencies):.3f} ms")
        if abe_latencies:
            lc[3].metric("ABE Avg Latency", f"{np.mean(abe_latencies):.3f} ms")

        st.divider()

        st.subheader("📈 Results")
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            fig1, ax1 = plt.subplots(figsize=(6, 4))
            ax1.scatter(range(len(aes_latencies)), aes_latencies,
                        s=8, alpha=0.5, color="#4C72B0", label="AES")
            ax1.scatter(range(len(abe_latencies)), abe_latencies,
                        s=8, alpha=0.5, color="#DD8452", label="ABE")
            ax1.set_title("AES vs ABE Latency (per request)")
            ax1.set_xlabel("Request index")
            ax1.set_ylabel("Latency (ms)")
            ax1.legend()
            ax1.grid(True)
            st.pyplot(fig1)

        with chart_col2:
            fig2, ax2 = plt.subplots(figsize=(6, 4))
            avgs = [np.mean(aes_latencies) if aes_latencies else 0,
                    np.mean(abe_latencies) if abe_latencies else 0]
            bars = ax2.bar(["AES-256-GCM", "ABE (SSS+AES-GCM)"], avgs,
                           color=["#4C72B0", "#DD8452"])
            for bar, val in zip(bars, avgs):
                ax2.text(bar.get_x() + bar.get_width() / 2, val,
                         f"{val:.3f} ms", ha='center', va='bottom', fontsize=10)
            ax2.set_title("Average Latency Comparison")
            ax2.set_ylabel("Latency (ms)")
            ax2.grid(True, axis='y')
            st.pyplot(fig2)

        pie_col1, pie_col2 = st.columns(2)

        with pie_col1:
            fig3, ax3 = plt.subplots(figsize=(5, 4))
            normal = processed - anomaly_count
            ax3.pie([normal, anomaly_count],
                    labels=["Normal", "Anomaly"],
                    colors=["#2ecc71", "#e74c3c"],
                    autopct="%1.1f%%", startangle=90)
            ax3.set_title("Anomaly Rate")
            st.pyplot(fig3)

        with pie_col2:
            fig4, ax4 = plt.subplots(figsize=(5, 4))
            ax4.pie([aes_count, abe_count, denied_count],
                    labels=["AES", "ABE", "Denied"],
                    colors=["#4C72B0", "#DD8452", "#95a5a6"],
                    autopct="%1.1f%%", startangle=90)
            ax4.set_title("Request Breakdown")
            st.pyplot(fig4)

        st.divider()

        st.subheader("📄 Request Log (last 50)")
        df_log = pd.DataFrame(log_rows).tail(50)
        st.dataframe(df_log, use_container_width=True)


# ==========================================
# TAB 3 — ML EVALUATION
# ==========================================
with tab3:
    st.header("🧠 ML Evaluation — Random Forest Anomaly Detector")
    st.markdown(
        "Trains the Random Forest on 1000 simulated access logs and evaluates it with "
        "accuracy, precision, recall, F1-score, 5-fold cross-validation, and a confusion matrix."
    )

    run_eval = st.button("▶ Run ML Evaluation", type="primary")

    if not run_eval:
        st.info("Click **Run ML Evaluation** to train and evaluate the Random Forest model.")
    else:
        with st.spinner("Training and evaluating Random Forest..."):
            results = evaluate_model(save_path="results/confusion_matrix.png")

        st.divider()

        st.subheader("📋 Model Performance Metrics")
        mc = st.columns(4)
        mc[0].metric("Accuracy",  f"{results['accuracy']:.4f}",  help="Overall correct predictions / total")
        mc[1].metric("Precision", f"{results['precision']:.4f}", help="True positives / (true + false positives)")
        mc[2].metric("Recall",    f"{results['recall']:.4f}",    help="True positives / (true positives + false negatives)")
        mc[3].metric("F1-Score",  f"{results['f1']:.4f}",        help="Harmonic mean of precision and recall")

        st.divider()
        st.subheader("🔁 5-Fold Cross-Validation")
        cv = results["cv_scores"]
        cv_cols = st.columns(7)
        for idx, score in enumerate(cv):
            cv_cols[idx].metric(f"Fold {idx+1}", f"{score:.4f}")
        cv_cols[5].metric("Mean", f"{cv.mean():.4f}")
        cv_cols[6].metric("Std Dev", f"{cv.std():.4f}")

        fig_cv, ax_cv = plt.subplots(figsize=(7, 3))
        ax_cv.bar([f"Fold {i+1}" for i in range(len(cv))], cv, color="#4C72B0", alpha=0.8)
        ax_cv.axhline(cv.mean(), color="#e74c3c", linestyle="--", label=f"Mean: {cv.mean():.4f}")
        ax_cv.set_ylim(0.85, 1.01)
        ax_cv.set_title("5-Fold Cross-Validation Accuracy")
        ax_cv.set_ylabel("Accuracy")
        ax_cv.legend()
        ax_cv.grid(True, axis='y')
        st.pyplot(fig_cv)

        st.divider()

        st.subheader("📊 Confusion Matrix & Metrics")
        cm_col1, cm_col2 = st.columns(2)

        with cm_col1:
            from sklearn.metrics import ConfusionMatrixDisplay
            fig_cm, ax_cm = plt.subplots(figsize=(5, 5))
            disp = ConfusionMatrixDisplay(
                confusion_matrix=results["confusion_matrix"],
                display_labels=["Normal", "Anomaly"]
            )
            disp.plot(ax=ax_cm, cmap="Blues", colorbar=False, values_format='d')
            ax_cm.set_title("Confusion Matrix — Anomaly Detection")
            st.pyplot(fig_cm)

        with cm_col2:
            fig_bar, ax_bar = plt.subplots(figsize=(5, 5))
            metrics     = ["Accuracy", "Precision", "Recall", "F1-Score"]
            values      = [results["accuracy"], results["precision"],
                           results["recall"], results["f1"]]
            colors      = ["#2ecc71", "#3498db", "#e67e22", "#9b59b6"]
            bars        = ax_bar.bar(metrics, values, color=colors, alpha=0.85)
            for bar, val in zip(bars, values):
                ax_bar.text(bar.get_x() + bar.get_width() / 2, val + 0.005,
                            f"{val:.4f}", ha='center', va='bottom', fontsize=11)
            ax_bar.set_ylim(0, 1.1)
            ax_bar.set_title("Model Performance Metrics")
            ax_bar.set_ylabel("Score")
            ax_bar.grid(True, axis='y')
            st.pyplot(fig_bar)

        st.divider()

        st.subheader("📁 Dataset Info")
        di = st.columns(3)
        di[0].metric("Total Samples", "1000")
        di[1].metric("Training Set", "800 (80%)")
        di[2].metric("Test Set", "200 (20%)")


# ==========================================
# TAB 4 — DATABASE EXPLORER
# ==========================================
with tab4:
    st.header("🗄️ Database Explorer — Real Encrypted Records")
    st.markdown(
        "Select a real record from the database, run it through the RCS "
        "encryption pipeline, and store the encrypted blob back. "
        "Then decrypt it to prove end-to-end data protection."
    )

    TABLE_LABELS = {
        "medical_records":   "🏥 Medical Records   (sensitivity: HIGH)",
        "financial_records": "💰 Financial Records (sensitivity: HIGH)",
        "hr_records":        "👤 HR Records        (sensitivity: MEDIUM)",
        "documents":         "📄 Documents         (sensitivity: LOW/MEDIUM)",
    }

    selected_label = st.selectbox("Select data category:", list(TABLE_LABELS.values()))
    table = [k for k, v in TABLE_LABELS.items() if v == selected_label][0]

    records = get_all_records(table)
    if not records:
        st.warning("No records found. Database may not be initialized.")
        st.stop()

    def record_label(r, t):
        if t == "medical_records":   return f"#{r['id']} — {r['patient']} ({r['diagnosis']})"
        if t == "financial_records": return f"#{r['id']} — {r['holder']} | {r['txn_type']} ₹{r['amount']:,.0f}"
        if t == "hr_records":        return f"#{r['id']} — {r['employee']} | {r['role']}"
        if t == "documents":         return f"#{r['id']} — {r['title']} ({r['category']})"
        return f"#{r['id']}"

    options     = {record_label(r, table): r["id"] for r in records}
    chosen_lbl  = st.selectbox("Select a record:", list(options.keys()))
    record_id   = options[chosen_lbl]
    record      = get_record(table, record_id)
    plaintext   = get_plaintext_summary(record, table)
    sensitivity_class = record.get("sensitivity", "MEDIUM")
    base_score  = SENSITIVITY_MAP[sensitivity_class]

    st.divider()

    st.subheader("📋 Record Details")
    detail_cols = st.columns(3)
    detail_cols[0].metric("Record ID",              f"#{record_id}")
    detail_cols[1].metric("Classification",         sensitivity_class)
    detail_cols[2].metric("Base Sensitivity Score", f"{base_score:.2f}")

    enc_status = "🔒 Encrypted" if record["encrypted"] else "🔓 Plaintext"
    if record["encrypted"]:
        st.warning(f"Status: {enc_status} — currently stored as `{record['enc_scheme']}` ciphertext")
    else:
        st.success(f"Status: {enc_status} — plaintext visible")
        st.code(plaintext, language="text")

    st.divider()

    st.subheader("🔐 Encrypt This Record")

    if record["encrypted"]:
        st.info("This record is already encrypted. Decrypt it first before re-encrypting.")
    else:
        threat_db    = st.slider("Threat level for this request", 0.0, 1.0, 0.5, key="db_threat")
        final_score  = 0.4 * base_score + 0.3 * base_score + 0.3 * threat_db
        scheme_chosen = "ABE" if final_score > 0.6 else "AES-256-GCM"

        sc1, sc2 = st.columns(2)
        sc1.metric("Final Sensitivity Score",   f"{final_score:.4f}")
        sc2.metric("Encryption Scheme Selected", scheme_chosen)

        if scheme_chosen == "ABE":
            st.info("🔐 High sensitivity → **ABE (SSS+AES-GCM)** will be used. Policy: `role:admin` AND `region:india`")
        else:
            st.info("⚡ Lower sensitivity → **AES-256-GCM** will be used.")

        if st.button("🔐 Encrypt & Store in Database", type="primary", key="db_encrypt_btn"):
            with st.spinner("Encrypting and storing..."):
                if scheme_chosen == "ABE":
                    policy_db = {"role:admin", "region:india"}
                    blob = abe_encrypt(plaintext, policy_db, policy_db)
                    encrypt_and_store(table, record_id, "ABE", blob)
                else:
                    blob = aes_encrypt_for_storage(plaintext)
                    encrypt_and_store(table, record_id, "AES-256-GCM", blob)
            st.success(f"✅ Record #{record_id} encrypted with **{scheme_chosen}** and stored in the database.")
            st.rerun()

    st.divider()

    st.subheader("🔓 Decrypt This Record")

    if not record["encrypted"]:
        st.info("This record is not encrypted yet. Encrypt it first.")
    else:
        st.markdown(f"Stored as: `{record['enc_scheme']}`")

        if record["enc_scheme"] == "AES-256-GCM":
            if st.button("🔓 Decrypt with AES Key", type="primary", key="db_decrypt_aes"):
                result = decrypt_record(table, record_id)
                if result:
                    st.success("✅ Decryption successful!")
                    st.code(result, language="text")
                else:
                    st.error("❌ Decryption failed.")

        elif record["enc_scheme"] == "ABE":
            st.markdown("ABE policy requires: `role:admin` AND `region:india`")
            user_attrs_db = st.multiselect(
                "Select your attributes:",
                ["role:admin", "role:user", "region:india", "region:us"],
                default=["role:admin", "region:india"],
                key="db_abe_attrs"
            )
            if st.button("🔓 Decrypt with ABE Attributes", type="primary", key="db_decrypt_abe"):
                result = decrypt_record(table, record_id, user_attrs=user_attrs_db)
                if result:
                    st.success("✅ Decryption successful!")
                    st.code(result, language="text")
                    st.balloons()
                else:
                    st.error(
                        f"❌ Decryption failed — your attributes `{user_attrs_db}` "
                        f"do not satisfy the policy. AES-GCM tag verification failed."
                    )

        if st.button("🔄 Reset Record (clear encryption)", key="db_reset_btn"):
            reset_record(table, record_id)
            st.success("Record reset to plaintext state.")
            st.rerun()

    st.divider()

    st.subheader("📊 All Records in This Table")
    df = pd.DataFrame(records)
    display_cols = [c for c in df.columns if c not in ["enc_blob"]]
    st.dataframe(df[display_cols], use_container_width=True)

    total     = len(records)
    encrypted = sum(1 for r in records if r["encrypted"])
    sc = st.columns(3)
    sc[0].metric("Total Records", total)
    sc[1].metric("Encrypted",     encrypted)
    sc[2].metric("Plaintext",     total - encrypted)