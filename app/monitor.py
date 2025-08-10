import psutil
import time
import json
import os
from datetime import datetime

LOG_FILE = "data/behavior_log.json"

def collect_process_data():
    snapshot = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            info = proc.info
            info["timestamp"] = datetime.now().isoformat()
            snapshot.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return snapshot

def append_to_log(data):
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    
    with open(LOG_FILE, "r+") as f:
        logs = json.load(f)
        logs.extend(data)
        f.seek(0)
        json.dump(logs, f, indent=2)

if __name__ == "__main__":
    while True:
        processes = collect_process_data()
        append_to_log(processes)
        print(f"Logged {len(processes)} processes.")
        time.sleep(5)
