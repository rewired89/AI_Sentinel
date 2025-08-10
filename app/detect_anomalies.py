from win10toast import ToastNotifier
import psutil
import time
import pandas as pd
import joblib
import os
import json
import zipfile
from datetime import datetime

# Initialize notifier
toast = ToastNotifier()

# Trusted processes to skip
WHITELIST = [
    "firefox.exe", "chrome.exe", "code.exe", "python.exe", "explorer.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "taskmgr.exe",
    "svchost.exe", "System", "System Idle Process", "SearchIndexer.exe",
    "RuntimeBroker.exe", "winlogon.exe", "lsass.exe", "csrss.exe"
]

# Known suspicious/hacker tools
BLACKLIST = [
    "mimikatz.exe", "nmap.exe", "wireshark.exe", "aircrack-ng.exe",
    "metasploit.exe", "burpsuite.exe", "netcat.exe", "nc.exe",
    "hydra.exe", "john.exe", "sqlmap.exe", "ettercap.exe", "beef.exe",
    "msfconsole.exe", "tcpdump.exe", "hashcat.exe", "crackmapexec.exe"
]

MODEL_FILE = "model/anomaly_detector.pkl"
LOG_FILE = "data/anomalies_log.json"
QUARANTINE_DIR = "data/quarantine"
RAM_THRESHOLD_MB = 500  # Flag any process using more than 500 MB of RAM

# Load ML model
model = joblib.load(MODEL_FILE)

def collect_current_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'username']):
        try:
            info = proc.info
            if info["name"] == "System Idle Process":
                continue
            mem_rss = proc.memory_info().rss / (1024 * 1024)  # Convert to MB
            info["memory_rss"] = round(mem_rss, 2)
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def detect(processes):
    df = pd.DataFrame(processes)
    if df.empty:
        return []

    df["timestamp"] = datetime.now().isoformat()
    features = df[["pid", "cpu_percent"]].fillna(0)
    predictions = model.predict(features)

    df["prediction"] = predictions

    # Flag processes either by ML or high RAM usage or BLACKLIST
    anomalies = df[
        (
            (df["prediction"] == -1) |
            (df["memory_rss"] > RAM_THRESHOLD_MB) |
            (df["name"].str.lower().isin([b.lower() for b in BLACKLIST]))
        ) &
        (~df["name"].isin(WHITELIST))
    ]

    return anomalies.to_dict(orient="records")

def log_anomalies(anomalies):
    if not anomalies:
        return
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    with open(LOG_FILE, "r+") as f:
        data = json.load(f)
        data.extend(anomalies)
        f.seek(0)
        json.dump(data, f, indent=2)

def quarantine_process(anomaly):
    try:
        pid = anomaly["pid"]
        proc = psutil.Process(pid)
        proc.suspend()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{anomaly['name']}_{pid}_{timestamp}"
        json_file = os.path.join(QUARANTINE_DIR, f"{base_name}.json")
        zip_file = os.path.join(QUARANTINE_DIR, f"{base_name}.zip")

        metadata = {
            "name": anomaly["name"],
            "pid": pid,
            "cpu_percent": anomaly.get("cpu_percent", 0),
            "memory_rss_MB": anomaly.get("memory_rss", 0),
            "timestamp": anomaly["timestamp"],
            "user": anomaly.get("username", "unknown")
        }

        with open(json_file, "w") as f:
            json.dump(metadata, f, indent=2)

        with zipfile.ZipFile(zip_file, 'w') as zipf:
            zipf.write(json_file, arcname=os.path.basename(json_file))

        os.remove(json_file)

        proc.kill()
        print(f"☠️  Quarantined and killed: {anomaly['name']} (PID {pid})")

        toast.show_toast(
            "🧪 AI Hunter Quarantine",
            f"{anomaly['name']} (PID {pid}) quarantined and terminated.",
            duration=5
        )

    except Exception as e:
        print(f"❌ Failed to quarantine {anomaly['name']} (PID {anomaly['pid']}): {e}")

# Main loop
def main():
    print("Running anomaly detection with Smart Quarantine...")

    found = False
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            cpu = proc.info['cpu_percent']
            ram = proc.info['memory_info'].rss / (1024 * 1024)
            if cpu > 50 or ram > 100:
                print(f"⚠️  Anomaly detected: {proc.info['name']} (PID {proc.info['pid']})")
                found = True
        except Exception:
            continue

    if not found:
        print("✅ No anomalies found.")
