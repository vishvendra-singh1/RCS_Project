print(">>> main.py started")

import warnings
warnings.filterwarnings("ignore")

import random
import time
import matplotlib.pyplot as plt
import numpy as np

from acl.rbac import rbac
from acl.abac import abac
from encryption.sensitivity import sensitivity
from encryption.aes_encrypt import aes_encrypt
from encryption.abe import abe_encrypt
from anomaly.train_rf import train_model
from anomaly.detect import detect_anomaly

TOTAL_REQUESTS = 500
SLEEP_BETWEEN_REQUESTS = 0.005  # kept small so 500 requests don't take forever


def main():
    model = train_model()

    aes_latencies = []   # ms, indexed by request number (None if not AES)
    abe_latencies = []   # ms, indexed by request number (None if not ABE)

    denied_count = 0
    aes_count = 0
    abe_count = 0
    anomaly_count = 0

    sim_start = time.perf_counter()

    for i in range(TOTAL_REQUESTS):
        role = random.choice(["admin", "user"])
        env = {"location": "India", "time": random.randint(0, 23)}

        # ---- Access Control (RBAC + ABAC) ----
        if not rbac(role, "read") or not abac(env):
            denied_count += 1
            aes_latencies.append(None)
            abe_latencies.append(None)
            continue

        # ---- Sensitivity scoring for this request ----
        conf = random.random()
        threat = random.random()
        s = sensitivity(conf, 1, threat)
        data = "Confidential Data"

        # Derive anomaly-detection features from THIS request, rather than
        # generating disconnected random numbers. This keeps the anomaly
        # check meaningful and traceable back to the request that triggered it.
        entropy = s                              # composite sensitivity score, 0-1
        rate = (i % 100) + random.uniform(0, 5)   # simple proxy for request rate
        volume = random.uniform(50, 500)          # simulated payload size

        # ---- Encryption: ABE for high sensitivity, AES otherwise ----
        if s > 0.6:
            # Realistic multi-attribute policy: data requires the requester
            # to hold the role attribute AND be accessing from the
            # correct region (2-of-2 AND policy by default).
            policy = {f"role:{role}", "region:india"}

            start = time.perf_counter()
            encrypted = abe_encrypt(data, policy, policy)
            latency = (time.perf_counter() - start) * 1000  # ms

            abe_latencies.append(latency)
            aes_latencies.append(None)
            abe_count += 1
            tag = "ABE Applied 🔐"
        else:
            start = time.perf_counter()
            encrypted = aes_encrypt(data)
            latency = (time.perf_counter() - start) * 1000  # ms

            aes_latencies.append(latency)
            abe_latencies.append(None)
            aes_count += 1
            tag = "AES Applied 🔑"

        # ---- Anomaly Detection (now scored on real request features) ----
        is_anomaly = detect_anomaly(model, entropy, rate, volume)
        if is_anomaly:
            anomaly_count += 1
            tag += "  ⚠️ Anomaly Detected"

        # Print every 25th request so the console stays readable at 500 requests
        if (i + 1) % 25 == 0 or i < 5:
            print(f"[{i+1}/{TOTAL_REQUESTS}] {tag}")

        time.sleep(SLEEP_BETWEEN_REQUESTS)

    sim_end = time.perf_counter()
    total_time = sim_end - sim_start

    # =======================
    # 📊 SUMMARY METRICS
    # =======================
    valid_aes = [x for x in aes_latencies if x is not None]
    valid_abe = [x for x in abe_latencies if x is not None]
    processed = aes_count + abe_count
    throughput = processed / total_time if total_time > 0 else 0

    print("\n" + "=" * 50)
    print("SIMULATION SUMMARY")
    print("=" * 50)
    print(f"Total requests simulated : {TOTAL_REQUESTS}")
    print(f"Access denied (RBAC/ABAC): {denied_count}")
    print(f"Processed requests       : {processed}")
    print(f"  - AES applied          : {aes_count}")
    print(f"  - ABE applied          : {abe_count}")
    print(f"Anomalies detected       : {anomaly_count}")
    print(f"Total simulation time    : {total_time:.3f} s")
    print(f"Throughput               : {throughput:.2f} requests/sec")

    if valid_aes:
        print(f"\nAES Latency  -> avg: {np.mean(valid_aes):.3f} ms | "
              f"min: {np.min(valid_aes):.3f} ms | max: {np.max(valid_aes):.3f} ms")
    if valid_abe:
        print(f"ABE Latency  -> avg: {np.mean(valid_abe):.3f} ms | "
              f"min: {np.min(valid_abe):.3f} ms | max: {np.max(valid_abe):.3f} ms")
    print("=" * 50 + "\n")

    # =======================
    # 📈 GRAPH
    # =======================
    plt.style.use('ggplot')
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # --- Raw latency scatter (left) ---
    aes_y = [x for x in aes_latencies if x is not None]
    abe_y = [x for x in abe_latencies if x is not None]
    aes_x = list(range(len(aes_y)))
    abe_x = list(range(len(abe_y)))

    axes[0].plot(aes_x, aes_y, 'o', markersize=3, alpha=0.6, label="AES Latency")
    axes[0].plot(abe_x, abe_y, 'x', markersize=3, alpha=0.6, label="ABE Latency")
    axes[0].set_title("AES vs ABE Latency (per request)")
    axes[0].set_xlabel("Request index (within type)")
    axes[0].set_ylabel("Latency (ms)")
    axes[0].legend()
    axes[0].grid(True)

    # --- Bar chart comparing averages (right) ---
    avg_aes = np.mean(aes_y) if aes_y else 0
    avg_abe = np.mean(abe_y) if abe_y else 0
    axes[1].bar(["AES", "ABE"], [avg_aes, avg_abe], color=["#4C72B0", "#DD8452"])
    axes[1].set_title("Average Latency Comparison")
    axes[1].set_ylabel("Latency (ms)")
    for idx, val in enumerate([avg_aes, avg_abe]):
        axes[1].text(idx, val, f"{val:.2f} ms", ha='center', va='bottom')
    axes[1].grid(True, axis='y')

    plt.tight_layout()
    plt.savefig("results/comparison.png", dpi=150)
    plt.show()


if __name__ == "__main__":
    main()