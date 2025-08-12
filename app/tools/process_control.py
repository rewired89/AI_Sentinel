# app/tools/process_control.py
import os
import shutil
import subprocess
import hashlib
import time
import psutil
import tempfile

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def kill_and_quarantine(proc):
    """
    Terminates a suspicious process and copies its executable to a quarantine folder.
    Returns dict: {"quarantine_path": <str>, "sha256": <str>}
    """
    p = psutil.Process(proc.pid) if not isinstance(proc, psutil.Process) else proc
    exe = p.exe()

    # try graceful, then force
    p.terminate()
    try:
        p.wait(timeout=3)
    except psutil.TimeoutExpired:
        p.kill()
        p.wait(timeout=2)

    # quarantine (copy then attempt to remove original)
    qdir = os.path.join(tempfile.gettempdir(), "AIHunterQuarantine")
    os.makedirs(qdir, exist_ok=True)
    base = os.path.basename(exe)
    dst = os.path.join(qdir, f"{int(time.time())}_{base}")
    shutil.copy2(exe, dst)

    file_hash = sha256_file(dst)
    try:
        os.remove(exe)  # may fail if locked; that's okay
    except Exception:
        pass

    return {"quarantine_path": dst, "sha256": file_hash}
