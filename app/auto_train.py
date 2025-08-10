import os
import time
import subprocess
from datetime import datetime, timedelta

RETRAIN_INTERVAL = 7  # days
TIMESTAMP_FILE = "data/last_trained.txt"

def get_last_trained():
    if not os.path.exists(TIMESTAMP_FILE):
        return None
    with open(TIMESTAMP_FILE, "r") as f:
        ts = f.read().strip()
        return datetime.fromisoformat(ts)

def save_timestamp():
    with open(TIMESTAMP_FILE, "w") as f:
        f.write(datetime.now().isoformat())

def retrain():
    print("[AutoTrain] Re-training model...")
    subprocess.run([r"C:\Users\melas\Desktop\AI-Hunter\venv\Scripts\python.exe", "app/train_model.py"])
    save_timestamp()
    print("[AutoTrain] Done.")

if __name__ == "__main__":
    last_trained = get_last_trained()
    now = datetime.now()

    if not last_trained or (now - last_trained).days >= RETRAIN_INTERVAL:
        retrain()
    else:
        days_left = RETRAIN_INTERVAL - (now - last_trained).days
        print(f"[AutoTrain] No retrain needed. {days_left} day(s) left.")
