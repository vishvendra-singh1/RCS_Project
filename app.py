import numpy as np
import streamlit as st
import time
import matplotlib.pyplot as plt
import random

from acl.rbac import rbac
from acl.abac import abac
from encryption.aes_encrypt import aes_encrypt
from encryption.abe import abe_encrypt, abe_decrypt
from encryption.sensitivity import sensitivity
from anomaly.train_rf import train_model
from anomaly.detect import detect_anomaly

# ---- Train the ML model once at app startup ----
@st.cache_resource
def load_model():
    return train_model()

# ---- Page config ----
st.set_page_config(page_title="RCS — Resilient Cloud Security", layout="wide")
st.title("🔐 Resilient Cloud Security (RCS) Framework")
st.markdown("Three-layer cloud security: **RBAC/ABAC Access Control → Sensitivity-Based Encryption → ML Anomaly Detection**")
st.divider()

# ---- Sidebar inputs ----
st.sidebar.header("👤 Simulate a Request")
role = st.sidebar.selectbox("User Role", ["admin", "user"])
location = st.sidebar.selectbox("Location", ["India", "US", "UK"])
time_val = st.sidebar.slider("Access Time (Hour)", 0, 23, 12)
data = st.sidebar.text_input("Data to Encrypt", "Confidential Cloud Data")
conf = st.sidebar.slider("Data Confidentiality (0–1)", 0.0, 1.0, 0.7)
threat = st.sidebar.slider("Threat Score (0–1)", 0.0, 1.0, 0.5)
run = st.sidebar.button("▶ Run Security Pipeline", type="primary")

if not run:
    st.info("Configure a request in the sidebar and click **Run Security Pipeline** to simulate all three security layers.")
    st.stop()

model = load_model()

# ======================
# LAYER 1: ACCESS CONTROL
# ======================
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
    st.stop()

st.success("✅ Access granted — proceeding to encryption layer")
st.divider()

# ======================
# LAYER 2: ENCRYPTION
# ======================
st.header("Layer 2 — Sensitivity-Based Encryption (AES-256-GCM / ABE)")

s = sensitivity(conf, 1, threat)
st.metric("Computed Sensitivity Score", f"{s:.4f}", help="Threshold: > 0.6 → ABE, ≤ 0.6 → AES")

col1, col2 = st.columns(2)

with col1:
    # Always benchmark AES for comparison
    aes_latencies = []
    for _ in range(10):
        start = time.perf_counter()
        aes_output = aes_encrypt(data)
        aes_latencies.append((time.perf_counter() - start) * 1000)
    aes_avg = np.mean(aes_latencies)
    st.metric("⚡ AES-256-GCM Avg Latency", f"{aes_avg:.4f} ms")

with col2:
    # Always benchmark ABE for comparison
    policy = {f"role:{role}", "region:india"}
    abe_latencies = []
    abe_pkg = None
    for _ in range(10):
        start = time.perf_counter()
        abe_pkg = abe_encrypt(data, policy, policy)
        abe_latencies.append((time.perf_counter() - start) * 1000)
    abe_avg = np.mean(abe_latencies)
    st.metric("🔐 ABE (SSS+AES-GCM) Avg Latency", f"{abe_avg:.4f} ms")

# Show which was chosen
if s > 0.6:
    chosen = "ABE"
    st.warning(f"🔐 Sensitivity {s:.4f} > 0.6 → **ABE** selected (policy: `{policy}`)")
    encrypted_output = abe_pkg
    # Verify decryption works with correct attrs
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

# Latency chart
fig, ax = plt.subplots(figsize=(7, 3))
ax.plot(aes_latencies, marker='o', label="AES-256-GCM", color="#4C72B0")
ax.plot(abe_latencies, marker='x', label="ABE (SSS+AES-GCM)", color="#DD8452")
ax.set_title("Encryption Latency — 10 runs")
ax.set_xlabel("Run")
ax.set_ylabel("Latency (ms)")
ax.legend()
ax.grid(True)
st.pyplot(fig)

st.divider()

# ======================
# LAYER 3: ANOMALY DETECTION
# ======================
st.header("Layer 3 — Anomaly Detection (Random Forest)")

entropy = s
rate = time_val * 4.0 + random.uniform(0, 5)   # proxy: busier during business hours
volume = conf * 500

col1, col2, col3 = st.columns(3)
col1.metric("Entropy (sensitivity)", f"{entropy:.4f}")
col2.metric("Rate (req proxy)", f"{rate:.2f}")
col3.metric("Volume (data size)", f"{volume:.1f}")

is_anomaly = detect_anomaly(model, entropy, rate, volume)

if is_anomaly:
    st.error("⚠️ **Anomaly Detected** — this request's access pattern was flagged by the Random Forest classifier as potentially malicious.")
else:
    st.success("✅ **Normal Access** — the Random Forest classifier found no anomaly in this request's access pattern.")

st.divider()

# ======================
# PIPELINE SUMMARY
# ======================
st.header("📊 Pipeline Summary")
summary_cols = st.columns(4)
summary_cols[0].metric("Access Control", "✅ Passed")
summary_cols[1].metric("Encryption Used", chosen)
summary_cols[2].metric("Sensitivity Score", f"{s:.4f}")
summary_cols[3].metric("Anomaly", "⚠️ Yes" if is_anomaly else "✅ No")