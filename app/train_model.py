import json
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

LOG_FILE = "data/behavior_log.json"
MODEL_FILE = "model/anomaly_detector.pkl"

# Load the behavior log
with open(LOG_FILE, "r") as f:
    data = json.load(f)

# Convert to DataFrame
df = pd.DataFrame(data)

# Keep only numeric fields for training
features = df[["pid", "cpu_percent"]]

# Train Isolation Forest
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(features)

# Save model to disk
joblib.dump(model, MODEL_FILE)

print(f"Model trained and saved to {MODEL_FILE}")
