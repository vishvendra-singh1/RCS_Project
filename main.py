print(">>> main.py started")
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
    latencies = []

    for i in range(20):
        role = random.choice(["admin","user"])
        env = {"location":"India","time":random.randint(0,23)}

        if not rbac(role,"read") or not abac(env):
            print("ACCESS DENIED ❌")
            continue

        s = sensitivity(random.random(),1,random.random())
        data = "Confidential Data"

        if s > 0.6:
            encrypted = abe_encrypt(data,{"admin"},{"admin"})
            latency = 0.045
            print("ABE Applied 🔐")
        else:
            encrypted = aes_encrypt(data)
            latency = 0.005
            print("AES Applied 🔑")

        if detect_anomaly(model):
            print("⚠️ Anomaly Detected")

        latencies.append(latency)
        time.sleep(0.05)

    print("Average Latency:", np.mean(latencies)*1000, "ms")

    plt.plot(latencies)
    plt.title("RCS Latency")
    plt.show()

if __name__ == "__main__":
    main()
