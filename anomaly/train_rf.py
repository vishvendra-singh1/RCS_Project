import random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def generate_logs(samples=1000):
    data = []
    for _ in range(samples):
        entropy = random.uniform(0,1)
        rate = random.uniform(0,100)
        volume = random.uniform(0,500)
        label = 1 if entropy > 0.7 and rate > 70 else 0
        data.append([entropy, rate, volume, label])
    return pd.DataFrame(data, columns=["entropy","rate","volume","label"])

def train_model():
    df = generate_logs()
    X = df[["entropy","rate","volume"]]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2)
    model = RandomForestClassifier(n_estimators=100, max_depth=15)
    model.fit(X_train, y_train)
    return model
