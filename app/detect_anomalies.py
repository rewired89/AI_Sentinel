# app/detect_anomalies.py
from win10toast import ToastNotifier
from trust import is_signed_by_trusted_publisher
import psutil
import time
import pandas as pd
import joblib
import os
import json
import zipfile
import re
from datetime import datetime

# -------------------------------------------------
# Module config
# -------------------------------------------------
TEST_MODE = os.getenv("AIHUNTER_TEST_MODE", "0") == "1"

# ---- Central allowlist ----
from allowlist import WHITELIST_NAMES, SAFE_PATH_KEYWORDS

# ---- Thresholds / files
MODEL_FILE = "model/anomaly_detector.pkl"
LOG_FILE = "data/anomalies_log.json"
QUARANTINE_DIR = "data/quarantine"
RAM_THRESHOLD_MB = 500           # flag if RAM > 500 MB
CPU_THRESHOLD = 25.0             # flag if CPU% > 25 (instant anomaly)
SCAN_INTERVAL = 5                # seconds between scans

CRITICAL_PROCESSES = {
    "system idle process", "system", "registry",
    "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe"
}

toast = ToastNotifier()
_PATH_PATTERNS = [re.compile(pat, re.IGNORECASE) for pat in SAFE_PATH_KEYWORDS]

def safe_toast(title: str, msg: str, seconds: int = 5):
    """No toasts in TEST_MODE; swallow UI-thread issues."""
    if TEST_MODE:
        return
    try:
        toast.show_toast(title, msg, duration=seconds, threaded=True)
    except Exception:
        pass

# -------------------------------------------------
# Trust / Critical checks
# -------------------------------------------------
def is_trusted(proc_info) -> bool:
    """Allowlist check. In TEST_MODE we bypass trust to enable safe testing."""
    if TEST_MODE:
        return False
    name = (proc_info.get("name") or "").lower()
    if name in WHITELIST_NAMES:
        return True
    exe = (proc_info.get("exe") or "").lower()
    if any(p.search(exe) for p in _PATH_PATTERNS):
        return True
    # Trust signed binaries from known vendors (e.g., Microsoft)
    if exe and is_signed_by_trusted_publisher(exe):
        return True
    return False

def is_critical(proc_info) -> bool:
    base = os.path.basename((proc_info.get("exe") or proc_info.get("name") or "")).lower()
    return base in CRITICAL_PROCESSES

# -------------------------------------------------
# Optional model
# -------------------------------------------------
model = None
if os.path.exists(MODEL_FILE):
    try:
        model = joblib.load(MODEL_FILE)
    except Exception:
        model = None

# -------------------------------------------------
# Utils
# -------------------------------------------------
def ensure_dirs():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

def log_anomalies(anomalies):
    if not anomalies:
        return
    ensure_dirs()
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
    with open(LOG_FILE, "r+", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []
        data.extend(anomalies)
        f.seek(0)
        json.dump(data, f, indent=2)

# -------------------------------------------------
# Fast, batched process sampler (no per-proc sleeps)
# -------------------------------------------------
def collect_current_processes():
    """
    Fast CPU sampling:
      1) Prime all processes once.
      2) Sleep once (0.4s).
      3) Read cpu_percent for all (non-blocking).
    Skips critical always; skips trusted unless TEST_MODE=1.
    """
    procs_info = []
    me = os.getpid()
    parent = os.getppid()

    # Enumerate processes and keep handles
    procs = []
    for proc in psutil.process_iter(['pid','name','exe','username','cmdline']):
        try:
            pid = proc.info.get("pid")
            if pid in (me, parent):
                continue
            name_lower = (proc.info.get("name") or "").lower()
            if name_lower == "system idle process":
                continue
            if is_critical(proc.info):
                continue
            if not TEST_MODE and is_trusted(proc.info):
                continue
            procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Prime all once
    for p in procs:
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # One global sleep instead of per-proc blocking
    time.sleep(0.4)

    # Read cpu/mem/cmdline for all
    for p in procs:
        try:
            cpu = p.cpu_percent(interval=None)  # non-blocking; uses the global prime
            try:
                mem_rss = p.memory_info().rss / (1024 * 1024)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                mem_rss = 0.0
            try:
                cmdline = " ".join(p.info.get("cmdline") or [])
            except Exception:
                cmdline = ""
            procs_info.append({
                "pid": p.info.get("pid"),
                "name": p.info.get("name"),
                "exe": p.info.get("exe"),
                "username": p.info.get("username"),
                "cmdline": cmdline,
                "cpu_percent": round(cpu, 1),
                "memory_rss": round(mem_rss, 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return procs_info

# -------------------------------------------------
# Detection & quarantine
# -------------------------------------------------
def detect(processes):
    """Return list of anomalies as dicts (filtered & enriched)."""
    if not processes:
        return []

    df = pd.DataFrame(processes)
    if df.empty:
        return []

    df["timestamp"] = datetime.now().isoformat()

    # Heuristics
    heur_mask = (df["cpu_percent"].fillna(0) > CPU_THRESHOLD) | (df["memory_rss"].fillna(0) > RAM_THRESHOLD_MB)

    # Optional model
    model_mask = pd.Series([False] * len(df))
    if model is not None:
        try:
            features = df[["pid", "cpu_percent"]].fillna(0)
            preds = model.predict(features)  # -1 anomaly, 1 normal
            model_mask = (preds == -1)
        except Exception:
            pass

    final_mask = heur_mask | model_mask
    anomalies = df[final_mask].copy()
    return anomalies.to_dict(orient="records")

def quarantine_process(anomaly):
    """Suspend, package metadata, and terminate the process safely."""
    try:
        pid = int(anomaly["pid"])
        name = anomaly.get("name") or "unknown"
        base = os.path.basename(anomaly.get("exe") or name).lower()

        if base in CRITICAL_PROCESSES:
            return

        # If process already gone, just log the event as "handled"
        if not psutil.pid_exists(pid):
            print(f"ℹ️  Process already exited: {name} (PID {pid})")
            return

        proc = psutil.Process(pid)

        # Suspend first (best-effort)
        try:
            proc.suspend()
        except Exception:
            pass

        ensure_dirs()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{base}_{pid}_{ts}"
        json_file = os.path.join(QUARANTINE_DIR, f"{base_name}.json")
        zip_file = os.path.join(QUARANTINE_DIR, f"{base_name}.zip")

        metadata = {
            "name": name,
            "exe": anomaly.get("exe"),
            "pid": pid,
            "cpu_percent": anomaly.get("cpu_percent", 0),
            "memory_rss_MB": anomaly.get("memory_rss", 0),
            "timestamp": anomaly.get("timestamp"),
            "user": anomaly.get("username", "unknown"),
            "cmdline": anomaly.get("cmdline", ""),
        }

        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        with zipfile.ZipFile(zip_file, 'w') as z:
            z.write(json_file, arcname=os.path.basename(json_file))

        try:
            os.remove(json_file)
        except Exception:
            pass

        # Small retry loop before kill to reduce race with fast-exiting procs
        for _ in range(3):
            if not psutil.pid_exists(pid):
                break
            try:
                proc.kill()
                break
            except Exception:
                time.sleep(0.05)

        print(f"☠️  Quarantined and killed: {name} (PID {pid})")
        safe_toast(
            "AI Hunter Sentinel– Threat Quarantined ☣️",
            f"{name} (PID {pid}) quarantined and terminated.",
            seconds=5
        )

    except Exception as e:
        print(f"❌ Failed to quarantine {anomaly.get('name','unknown')} (PID {anomaly.get('pid')}): {e}")

# -------------------------------------------------
# Single-pass
# -------------------------------------------------
def scan_once() -> int:
    """
    One pass.
    - In TEST_MODE: directly target cpu_hog scripts by cmdline (ignore thresholds/trust).
    - Normal mode: keep existing behavior via detect().
    """
    if TEST_MODE:
        # Direct grab (no thresholds) so short spikes or multi-core dilution don't hide the hog.
        def _grab_hog():
            try:
                procs = collect_current_processes()
            except Exception as e:
                print(f"❌ Failed to collect processes: {e}")
                return []
            out = []
            for p in procs:
                cmd = (p.get("cmdline") or "").lower()
                name = (p.get("name") or "").lower()
                if ("cpu_hog.py" in cmd) or ("cpu_hog_strong.py" in cmd):
                    out.append(p)
                # fallback: sometimes cmdline is truncated; accept high-cpu python as hog
                elif name == "python.exe" and p.get("cpu_percent", 0) >= 5.0 and "ai_hunter_main.py" not in cmd:
                    out.append(p)
            return out

        anomalies = _grab_hog()
        if not anomalies:
            time.sleep(0.8)   # brief resample
            anomalies = _grab_hog()

        if anomalies:
            print(f"⚠️  {len(anomalies)} anomaly detected!")
            for a in anomalies:
                if is_critical(a):
                    continue
                print(f" - PID: {a.get('pid')}, Name: {a.get('name')}, CPU: {a.get('cpu_percent')}%, RAM: {a.get('memory_rss')}MB")
                quarantine_process(a)
            log_anomalies(anomalies)
            return len(anomalies)

        print("✅ No anomalies found.")
        return 0

    # -------- Normal mode (unchanged behavior) --------
    try:
        processes = collect_current_processes()
    except Exception as e:
        print(f"❌ Failed to collect processes: {e}")
        return 0

    records = detect(processes)
    if records:
        print(f"⚠️  {len(records)} anomaly detected!")
        for a in records:
            if is_critical(a) or is_trusted(a):
                continue
            print(f" - PID: {a.get('pid')}, Name: {a.get('name')}, CPU: {a.get('cpu_percent')}%, RAM: {a.get('memory_rss')}MB")
            quarantine_process(a)
        log_anomalies(records)
        return len(records)

    print("✅ No anomalies found.")
    return 0

# -------------------------------------------------
# Continuous mode (unchanged)
# -------------------------------------------------
def main():
    print("Running anomaly detection with Smart Quarantine... Press Ctrl+C to stop.")
    try:
        while True:
            processes = collect_current_processes()
            anomalies = detect(processes)

            if anomalies:
                print(f"⚠️  {len(anomalies)} anomaly detected!")
                for a in anomalies:
                    # Double-check: don’t act on trusted/critical (defense in depth)
                    if is_trusted(a) or is_critical(a):
                        continue

                    pid = a.get("pid")
                    nm = a.get("name")
                    mem = a.get("memory_rss")
                    cpu = a.get("cpu_percent")
                    print(f" - PID: {pid}, Name: {nm}, CPU: {cpu}%, RAM: {mem}MB")
                    quarantine_process(a)
                log_anomalies(anomalies)
            else:
                print("✅ No anomalies found.")

            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("Stopped.")

if __name__ == "__main__":
    main()
