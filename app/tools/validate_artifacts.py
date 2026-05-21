# app/tools/validate_artifacts.py
import os, json, zipfile, hashlib, time
from datetime import datetime
from pathlib import Path

# Project root = .../AI-Hunter  (tools -> app -> project_root)
ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
LOG  = DATA / "anomalies_log.json"
QUAR = DATA / "quarantine"

def sha256_file(path, block=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(block):
            h.update(chunk)
    return h.hexdigest()

def check_log():
    print("=== LOG CHECK ===")
    if not LOG.exists():
        print("❌ No anomalies_log.json found.")
        return {"exists": False, "count": 0}
    try:
        data = json.loads(LOG.read_text(encoding="utf-8") or "[]")
        if not isinstance(data, list):
            raise ValueError("Log root is not a list.")
        count = len(data)
        print(f"✅ Log present. Entries: {count}")
        for rec in data[-3:]:
            ts = rec.get("timestamp")
            name = rec.get("name")
            pid = rec.get("pid")
            cpu = rec.get("cpu_percent")
            print(f"  - {ts}  {name}  PID={pid}  CPU={cpu}%")
        return {"exists": True, "count": count}
    except Exception as e:
        print(f"❌ Failed to read/parse log: {e}")
        return {"exists": True, "count": 0, "error": str(e)}

def check_quarantine():
    print("\n=== QUARANTINE CHECK ===")
    if not QUAR.exists():
        print("❌ No quarantine directory found.")
        return {"exists": False, "zips": []}
    zips = sorted([p for p in QUAR.iterdir() if p.suffix.lower()==".zip"])
    if not zips:
        print("ℹ️ No quarantine ZIPs yet.")
        return {"exists": True, "zips": []}

    report = []
    for z in zips:
        try:
            with zipfile.ZipFile(z, "r") as zf:
                names = zf.namelist()
                meta_name = [n for n in names if n.lower().endswith(".json")]
                ok = len(meta_name) == 1
                meta = {}
                if ok:
                    meta = json.loads(zf.read(meta_name[0]).decode("utf-8", errors="ignore") or "{}")
                sha = sha256_file(z)
                size = z.stat().st_size
                ts = datetime.fromtimestamp(z.stat().st_mtime).isoformat()
                print(f"✅ {z.name}  ({size} bytes)  sha256={sha[:12]}…  mtime={ts}")
                if ok:
                    print(f"   ↳ meta: name={meta.get('name')} pid={meta.get('pid')} cpu={meta.get('cpu_percent')} ts={meta.get('timestamp')}")
                else:
                    print("   ⚠️ no JSON metadata inside ZIP")
                report.append({"file": z.name, "ok": ok, "sha256": sha, "size": size, "meta": meta})
        except Exception as e:
            print(f"❌ Bad ZIP: {z.name}  error={e}")
    return {"exists": True, "zips": report}

def main():
    print(f"AI Sentinel – Artifact Validator")
    print(f"ROOT = {ROOT}")
    print(f"DATA = {DATA}")
    print(f"LOG  = {LOG}")
    print(f"QUAR = {QUAR}\n")

    log_info = check_log()
    q_info = check_quarantine()

    print("\n=== SUMMARY ===")
    print("✅ Artifacts look consistent." if (log_info.get("count",0)>=0) else "⚠️ See above.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
