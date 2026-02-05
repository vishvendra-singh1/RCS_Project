import numpy as np

def detect_anomaly(model):
    sample = np.array([[0.8, 90, 400]])
    prob = model.predict_proba(sample)[0][1]
    return prob > 0.7
