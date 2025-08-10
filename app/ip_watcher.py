from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

import psutil
import time
import requests
from win10toast import ToastNotifier
from dotenv import load_dotenv
import os
import subprocess
import json
from datetime import datetime

# Load environment variables
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Configs
BLOCK_THRESHOLD = 30
CHECK_INTERVAL = 10  # seconds
LOG_FILE = "data/blocked_ips_log.json"
seen_ips = set()
toast = ToastNotifier()

def get_threat_score(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 30
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data['data']['abuseConfidenceScore']
    except Exception as e:
        print(f"❌ API error for IP {ip}: {e}")
    return 0

def block_ip(ip, score):
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                       capture_output=True, text=True)
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Block_{ip}_out", "dir=out", "action=block", f"remoteip={ip}"],
                       capture_output=True, text=True)
        print(f"🛑 Blocked IP: {ip} (Score: {score})")
        toast.show_toast("🚨 AI Hunter – IP Blocked",
                         f"Blocked {ip} (Threat Score: {score})",
                         duration=5)

        log_ip(ip, score)

    except Exception as e:
        print(f"❌ Failed to block {ip}: {e}")

def log_ip(ip, score):
    record = {
        "ip": ip,
        "score": score,
        "timestamp": datetime.now().isoformat()
    }

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)

    with open(LOG_FILE, "r+") as f:
        try:
            data = json.load(f)
        except:
            data = []
        data.append(record)
        f.seek(0)
        json.dump(data, f, indent=2)

def get_active_ips():
    ips = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.status == 'ESTABLISHED':
            ip = conn.raddr.ip
            if ':' not in ip:  # Skip IPv6 for now
                ips.add(ip)
    return ips

def main():
    print("🔍 Watching for suspicious IP connections...")
    active_ips = get_active_ips()
    for ip in active_ips:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        score = get_threat_score(ip)
        print(f"IP: {ip} | Threat Score: {score}")
        if score >= BLOCK_THRESHOLD:
            block_ip(ip, score)
    print("✅ IP scan complete.")