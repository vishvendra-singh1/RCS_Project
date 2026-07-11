import os
import random
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, ConfusionMatrixDisplay
)


def generate_logs(samples=1000, noise_level=0.02, random_state=None):
    """
    Generates simulated access-log data for anomaly detection.

    A small amount of realistic noise is injected so the classes are not
    perfectly separable (real-world logs are never perfectly clean):
      - `noise_level` fraction of labels are randomly flipped, simulating
        mislabeled or ambiguous log entries.
      - Feature values get a small amount of Gaussian jitter so points
        near the decision boundary (entropy ~0.7, rate ~70) genuinely
        overlap between classes instead of being perfectly separable.
    """
    rng = random.Random(random_state)
    data = []
    for _ in range(samples):
        entropy = rng.uniform(0, 1)
        rate = rng.uniform(0, 100)
        volume = rng.uniform(0, 500)

        # Base rule, same as before
        label = 1 if entropy > 0.7 and rate > 70 else 0

        # Inject small Gaussian jitter into the features actually stored,
        # so points near the boundary look noisy/ambiguous rather than
        # perfectly clean — without changing the underlying label rule.
        entropy_noisy = min(1.0, max(0.0, entropy + rng.gauss(0, 0.03)))
        rate_noisy = min(100.0, max(0.0, rate + rng.gauss(0, 3)))

        # Randomly flip a small fraction of labels to simulate
        # mislabeled/ambiguous real-world log entries.
        if rng.random() < noise_level:
            label = 1 - label

        data.append([entropy_noisy, rate_noisy, volume, label])

    return pd.DataFrame(data, columns=["entropy", "rate", "volume", "label"])


def train_model():
    """
    Original lightweight training function used by main.py for the
    request simulation. Kept unchanged so main.py doesn't need edits.
    """
    df = generate_logs()
    X = df[["entropy", "rate", "volume"]]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    model = RandomForestClassifier(n_estimators=100, max_depth=15)
    model.fit(X_train, y_train)
    return model


def evaluate_model(samples=1000, cv_folds=5, save_path="results/confusion_matrix.png"):
    """
    Trains a Random Forest on the same simulated log data and produces
    a full evaluation report: accuracy, precision, recall, F1-score,
    k-fold cross-validation, and a saved confusion matrix heatmap.

    Run this directly (python anomaly/train_rf.py) to generate the
    evaluation report and figure for your project documentation.
    """
    df = generate_logs(samples, random_state=1)
    X = df[["entropy", "rate", "volume"]]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    # ---- Core metrics on held-out test set ----
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    # ---- K-fold cross-validation ----
    cv_model  = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
    cv_scores = cross_val_score(cv_model, X, y, cv=cv_folds, scoring="accuracy")

    # ---- Confusion matrix ----
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 50)
    print("ML MODEL EVALUATION — Random Forest Anomaly Detector")
    print("=" * 50)
    print(f"Dataset size          : {samples} samples")
    print(f"Train / Test split    : {len(X_train)} / {len(X_test)}")
    print(f"Class balance (label) :\n{y.value_counts().to_string()}")
    print("-" * 50)
    print(f"Accuracy  : {acc:.4f}")
    print(f"Precision : {prec:.4f}")
    print(f"Recall    : {rec:.4f}")
    print(f"F1-score  : {f1:.4f}")
    print("-" * 50)
    print(f"{cv_folds}-Fold Cross-Validation Accuracy Scores:")
    print("  " + ", ".join(f"{s:.4f}" for s in cv_scores))
    print(f"  Mean: {cv_scores.mean():.4f}  |  Std Dev: {cv_scores.std():.4f}")
    print("-" * 50)
    print("Confusion Matrix:")
    print(cm)
    print("=" * 50 + "\n")

    # ---- Save confusion matrix as an image ----
    fig, ax = plt.subplots(figsize=(5, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Anomaly"])
    disp.plot(ax=ax, cmap="Blues", colorbar=False, values_format='d')
    ax.set_title("Confusion Matrix — Anomaly Detection")
    plt.tight_layout()
    try:
        os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
        plt.savefig(save_path, dpi=150)
        print(f"Confusion matrix saved to: {save_path}")
    except Exception:
        pass  # skip saving on read-only filesystems (e.g. Streamlit Cloud)
    plt.close(fig)

    return {
        "accuracy":         acc,
        "precision":        prec,
        "recall":           rec,
        "f1":               f1,
        "cv_scores":        cv_scores,
        "confusion_matrix": cm,
    }


if __name__ == "__main__":
    evaluate_model()