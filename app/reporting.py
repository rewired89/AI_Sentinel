# app/reporting.py
import os, json, shutil, socket, zipfile, getpass, platform
from datetime import datetime, timedelta
from pathlib import Path

# -------- Constants --------
REPORTS_DIR_NAME = "AI Sentinel Reports"   # fixed folder name on Desktop
ENV_REPORTS_DIR  = "AIHUNTER_REPORTS_DIR"         # optional override: full path

# Project & data paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR     = PROJECT_ROOT / "data"
LOG_FILE     = DATA_DIR / "anomalies_log.json"
QUAR_DIR     = DATA_DIR / "quarantine"

def _desktop_path() -> Path:
    """Best-effort Desktop path (Windows), fallback to home if Desktop missing."""
    home = Path(os.path.expanduser("~"))
    desktop = home / "Desktop"
    return desktop if desktop.exists() else home

def _desktop_reports_root() -> Path:
    """
    Returns the reports root directory.
    Priority:
      1) AIHUNTER_REPORTS_DIR env var (absolute path)
      2) <Desktop>/AI Sentinel Reports
    """
    override = os.getenv(ENV_REPORTS_DIR, "").strip()
    if override:
        return Path(override).expanduser()
    return _desktop_path() / REPORTS_DIR_NAME

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _copy_recent_quarantine(dst_dir: Path, since: datetime, window_minutes: int = 15) -> list[Path]:
    if not QUAR_DIR.exists():
        return []
    out = []
    cutoff = since - timedelta(minutes=window_minutes)
    for z in sorted(QUAR_DIR.glob("*.zip")):
        try:
            mtime = datetime.fromtimestamp(z.stat().st_mtime)
            if mtime >= cutoff:
                shutil.copy2(z, dst_dir / z.name)
                out.append(dst_dir / z.name)
        except Exception:
            continue
    return out

def _write_text(path: Path, text: str):
    try:
        path.write_text(text, encoding="utf-8")
    except Exception:
        pass

def _zip_folder(src_dir: Path, zip_path: Path):
    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for p in src_dir.rglob("*"):
                if p.is_file():
                    z.write(p, p.relative_to(src_dir))
        return True
    except Exception:
        return False

def save_incident_report(trigger_time: datetime, findings: dict) -> Path:
    """
    Create a timestamped incident folder under:
      <Desktop>/AI Sentinel Reports/INCIDENT_YYYYMMDD_HHMMSS

    Contents:
      - report.json (summary & environment)
      - README.txt (how to send)
      - anomalies_log.json (if present)
      - recent quarantine ZIPs (last 15 min)
      - INCIDENT_*.zip (zip of the whole folder)
    Returns the incident folder path.
    """
    reports_root = _desktop_reports_root()
    _ensure_dir(reports_root)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    incident_dir = reports_root / f"INCIDENT_{ts}"
    _ensure_dir(incident_dir)

    # Copy anomalies log (if exists)
    if LOG_FILE.exists():
        try:
            shutil.copy2(LOG_FILE, incident_dir / LOG_FILE.name)
        except Exception:
            pass

    # Copy recent quarantine zips
    copied = _copy_recent_quarantine(incident_dir, since=trigger_time, window_minutes=15)

    # Build report.json
    env = {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "project_root": str(PROJECT_ROOT),
        "data_dir": str(DATA_DIR),
        "trigger_iso": trigger_time.isoformat(),
        "created_iso": datetime.now().isoformat(),
        "reports_root": str(reports_root),
    }
    report = {
        "summary": {
            "total_issues": int(findings.get("total", 0)),
            "by_component": {
                "process_anomalies": int(findings.get("process", 0)),
                "ip_reputation_hits": int(findings.get("ip", 0)),
                "otx_hits": int(findings.get("otx", 0)),
                "domain_flags": int(findings.get("domain", 0)),
            },
            "quarantine_files_copied": [p.name for p in copied],
        },
        "environment": env,
        "notes": "This package contains recent quarantine metadata and the anomalies log. Review before sending to support."
    }
    _write_text(incident_dir / "report.json", json.dumps(report, indent=2))

    # README.txt
    readme = f"""AI Sentinel – Incident Package

Created: {datetime.now().isoformat()}
Computer: {env['hostname']}  User: {env['username']}

What’s inside:
- report.json: summary + environment info
- anomalies_log.json: full anomaly log (if present)
- *.zip: quarantine metadata captured during/around this detection

To send to support:
1) Open this folder: {incident_dir}
2) Attach the ZIP file below to your email:
   -> {incident_dir.name}.zip
3) Or, if email blocks ZIPs, attach only report.json and the latest quarantine ZIP(s).

Privacy note: No file contents are collected; quarantine ZIPs contain only JSON metadata.
"""
    _write_text(incident_dir / "README.txt", readme)

    # Zip the incident folder
    _zip_folder(incident_dir, incident_dir.with_suffix(".zip"))

    return incident_dir
