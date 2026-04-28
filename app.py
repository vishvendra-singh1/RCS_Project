import numpy as np
import streamlit as st
import time
import matplotlib.pyplot as plt

# Import your functions
from acl.rbac import rbac
from acl.abac import abac
from encryption.aes_encrypt import aes_encrypt
from encryption.abe_simulated import abe_encrypt

def detect_anomaly(role, location, time_val):
    if role == "user" and location != "India":
        return True
    
    if time_val < 6 or time_val > 22:
        return True

    return False

st.set_page_config(page_title="AES vs ABE", layout="wide")

st.title("🔐 Resilient Cloud Security System")
st.markdown("Balancing Performance with Privacy in Cloud Systems")

# Input
st.subheader("👤 User Request")

col1, col2 = st.columns(2)

with col1:
    role = st.selectbox("User Role", ["admin", "user"])
    location = st.selectbox("Location", ["India", "US", "UK"])

with col2:
    time_val = st.slider("Access Time (Hour)", 0, 23, 12)
    data = st.text_input("Data to Access", "Confidential Data")
run = st.button("Run Encryption")
st.divider()

if run:
    chosen_algo = None
    st.divider()

    # 🔐 Access Control
    st.subheader("## 🔐 Access Control Decision")

    env = {"location": location, "time": time_val}

    if not rbac(role, "read"):
        st.error("Access Denied ❌ (RBAC Failed)")
        st.stop()

    if not abac(env):
        st.error("❌Policy Violaton: Unusual Location/Time")
        st.stop()
    else:
        st.success("Access Policy Valid✅")
    
    
        st.success(f"Access Granted ✅ | Role:{role} | Location: {location} | Time: {time_val}:00")
        # 🧠 Smart Decision
        st.subheader("Anomaly Detection")
        if detect_anomaly(role, location, time_val):
            st.warning("Suspicious Access Detected!")
        else:
            st.success("Normal Access Detected")

        st.subheader("🧠 Smart Encryption Decision")

        if detect_anomaly(role, location, time_val):
            chosen_algo = "ABE"
            st.warning("⚠️ Risk Detected → Using ABE")
        elif role == "admin" or "confidential" in data.lower():
            chosen_algo = "ABE"
            st.info("🔐 Using ABE → High Security")
        else:
            chosen_algo = "AES"
            st.info("⚡ Using AES → Fast & Efficient")
        st.info(f"🔍 Final Decision: {chosen_algo} selected based on risk & policy")

    aes_latencies = []
    abe_latencies = []

    for i in range(10):
        # AES
        start = time.perf_counter()
        for _ in range(100):
            aes_output = aes_encrypt(data)
        end = time.perf_counter()
        aes_latencies.append((end - start) * 1000 / 100)

        # ABE
        start = time.perf_counter()
        abe_output = abe_encrypt(data, {"A", "B"}, {"A"})
        end = time.perf_counter()
        abe_latencies.append((end - start) * 1000)

    # averages
    aes_avg = np.mean(aes_latencies)
    abe_avg = np.mean(abe_latencies)

    col1, col2 = st.columns(2)

    with col1:
        st.metric("🔐 AES Avg Latency", f"{aes_avg:.6f} ms")

    with col2:
        st.metric("🔑 ABE Avg Latency", f"{abe_avg:.3f} ms")

    if chosen_algo is None:
        st.error("❌ Encryption not performed due to policy violation")
        st.stop()
    # outputs
    st.subheader("🔐 Final Encryption Outputs")

    if chosen_algo == "AES":
        st.code(aes_output, language="text")
    else:
        st.code(abe_output, language="text")

    # graph
    fig, ax = plt.subplots()
    ax.plot(aes_latencies, marker='o', label="AES")
    ax.plot(abe_latencies, marker='x', label="ABE")

    ax.set_title("AES vs ABE Latency Comparison")
    ax.set_xlabel("Iterations")
    ax.set_ylabel("Latency (ms)")
    ax.legend()

    st.pyplot(fig)
