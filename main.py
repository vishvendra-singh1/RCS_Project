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
from encryption.abe_simulated import abe_encrypt
from anomaly.train_rf import train_model
from anomaly.detect import detect_anomaly


def main():
    model = train_model()

    aes_latencies = []
    abe_latencies = []

    # 🔁 Loop
    for i in range(20):
        role = random.choice(["admin", "user"])
        env = {"location": "India", "time": random.randint(0, 23)}

        # Access Control
        if not rbac(role, "read") or not abac(env):
            print("ACCESS DENIED ❌")

            # IMPORTANT → still append to maintain length
            aes_latencies.append(None)
            abe_latencies.append(None)
            continue

        # Sensitivity
        s = sensitivity(random.random(), 1, random.random())
        data = "Confidential Data"

        # 🔐 ABE (High sensitivity)
        if s > 0.6:
            start = time.perf_counter()
            encrypted = abe_encrypt(data, {"admin"}, {"admin"})
            latency = time.perf_counter() - start

            abe_latencies.append(latency)
            aes_latencies.append(None)

            print("ABE Applied 🔐")

        # 🔑 AES (Low sensitivity)
        else:
            start = time.perf_counter()
            encrypted = aes_encrypt(data)
            latency = time.perf_counter() - start

            aes_latencies.append(latency)
            abe_latencies.append(None)

            print("AES Applied 🔑")

        # 🚨 Anomaly Detection
        if detect_anomaly(model):
            print("⚠️ Anomaly Detected")

        time.sleep(0.05)

    # =======================
    # 📊 AVERAGES
    # =======================

    valid_aes = [x for x in aes_latencies if x is not None]
    valid_abe = [x for x in abe_latencies if x is not None]

    if valid_aes:
        print("Average AES Latency:", np.mean(valid_aes) * 1000, "ms")

    if valid_abe:
        print("Average ABE Latency:", np.mean(valid_abe) * 1000, "ms")

    # =======================
    # 📈 GRAPH
    # =======================
    plt.style.use('ggplot')
    plt.figure(figsize=(10, 5))

    # Remove None values completely
    aes_y = [x for x in aes_latencies if x is not None]
    abe_y = [x for x in abe_latencies if x is not None]

    #Convert to milliseconds
    aes_y = [x*1000 for x in aes_y]
    abe_y = [x*1000 for x in abe_y]

    # Create separate x-axis
    aes_x = list(range(len(aes_y)))
    abe_x = list(range(len(abe_y)))

    # Plot
    plt.plot(aes_x, aes_y, '-o', label="AES Latency")
    plt.plot(abe_x, abe_y, '-x', label="ABE Latency")
    plt.ylim(0, max(max(aes_y),max(abe_y))*1.2)
    plt.title("AES vs ABE Latency Comparison")
    plt.xlabel("Iterations (separate)")
    plt.ylabel("Latency (ms)")
    plt.legend()
    plt.grid(True)

    plt.savefig("results/comparison.png")
    plt.show()

if __name__ == "__main__":
    main()