import numpy as np

def detect_anomaly(model, entropy, rate, volume):
    """
    Score a single request for anomalous behavior.

    Features must match training set in train_rf.py: [entropy, rate, volume]
    These are now passed in from the actual request being processed in main.py,
    instead of being generated independently — so a detected anomaly is tied
    to a real request's characteristics, not a disconnected random sample.
    """
    X = np.array([[entropy, rate, volume]])
    prediction = model.predict(X)
    return prediction[0] == 1