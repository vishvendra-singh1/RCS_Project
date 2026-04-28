import numpy as np
import random

def detect_anomaly(model):
    # 3 features (must match training)
    role = random.randint(0,1)
    time = random.randint(0,23)
    extra = random.random()

    X = np.array([[role, time, extra]])

    prediction = model.predict(X)

    return prediction[0] == 1