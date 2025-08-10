from dotenv import load_dotenv
import os
import psutil
import time
import requests
from win10toast import ToastNotifier
import socket
import subprocess
from datetime import datetime
import json
import tkinter as tk
from tkinter import messagebox

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Config
CHECK_INTERVAL = 10  # seconds
DOMAIN_CACHE = {}
BAD_DOMAINS = set()
BLOCKED_IPS = set()
LOG_FILE = "threat_report.txt"
BEHAVIOR_POLICY_FILE = "behavior_policy.json"
CRITICAL_PROCESSES = {
    "System Idle Process", "System", "Registry", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "SearchProtocolHost.exe", "audiodg.exe",
    "RuntimeBroker.exe", "fontdrvhost.exe", "dwm.exe", "WUDFHost.exe", "spoolsv.exe", "conhost.exe",
    "MsMpEng.exe", "SearchIndexer.exe", "SecurityHealthService.exe", "SecurityHealthSystray.exe",
    "smartscreen.exe", "ApplicationFrameHost.exe", "ctfmon.exe", "OneDrive.exe"
}

toast = ToastNotifier()

# Load saved behavior policy
if os.path.exists(BEHAVIOR_POLICY_FILE):
    with open(BEHAVIOR_POLICY_FILE, "r") as f:
        behavior_policy = json.load(f)
else:
    behavior_policy = {}

def log_event(event_type, ip, domain, score):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] {event_type} | IP: {ip} | Domain: {domain} | Score: {score}\n")

def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def get_domain_report(domain):
    if domain in DOMAIN_CACHE:
        return DOMAIN_CACHE[domain]

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            last_analysis = data["data"]["attributes"]["last_analysis_stats"]
            malicious = last_analysis.get("malicious", 0)
            DOMAIN_CACHE[domain] = malicious
            return malicious
        else:
            return 0
    except:
        return 0

def block_ip(ip):
    if ip in BLOCKED_IPS:
        return
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                       capture_output=True, text=True)
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Block_{ip}_out", "dir=out", "action=block", f"remoteip={ip}"],
                       capture_output=True, text=True)
        print(f"🛑 Blocked domain IP: {ip}")
        toast.show_toast("AI Hunter – Domain Blocked 🚫", f"Blocked domain IP: {ip}", duration=5)
        BLOCKED_IPS.add(ip)
    except Exception as e:
        print(f"❌ Failed to block IP {ip}: {e}")

def get_active_ips():
    ips = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.status == 'ESTABLISHED':
            ip = conn.raddr.ip
            if ':' not in ip:
                ips.add(ip)
    return ips

def show_popup(title, message):
    root = tk.Tk()
    root.withdraw()
    return messagebox.askyesno(title, message)

def ask_user_behavior(process_path):
    process_name = os.path.basename(process_path)
    if process_name in CRITICAL_PROCESSES:
        return

    print(f"⚠️ Suspicious process detected: {process_path}")
    user_choice = show_popup("AI Hunter – Behavior Alert ⚠️", f"Suspicious process:\n{process_path}\n\nAllow this process?")

    if user_choice:
        behavior_policy[process_path] = "allow"
    else:
        behavior_policy[process_path] = "block"
        try:
            subprocess.run(["taskkill", "/F", "/IM", process_name], capture_output=True)
            print(f"🛑 Blocked and killed process: {process_path}")
            toast.show_toast("AI Hunter – Process Blocked 🚫", f"Blocked: {process_path}", duration=5)
        except Exception as e:
            print(f"❌ Failed to block process {process_path}: {e}")

    with open(BEHAVIOR_POLICY_FILE, "w") as f:
        json.dump(behavior_policy, f, indent=2)

def run_behavior_protection():
    seen = set()
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = proc.info['exe'] or proc.info['name']
            process_name = os.path.basename(exe_path or '')
            if process_name in CRITICAL_PROCESSES:
                continue
            if exe_path and exe_path not in seen:
                seen.add(exe_path)
                action = behavior_policy.get(exe_path)
                if action == "block":
                    subprocess.run(["taskkill", "/F", "/IM", os.path.basename(exe_path)], capture_output=True)
                    print(f"🛑 Auto-blocked: {exe_path}")
                    toast.show_toast("AI Hunter – Auto Block 🚫", f"Blocked: {exe_path}", duration=5)
                elif action != "allow":
                    ask_user_behavior(exe_path)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def main():
    print("🌐 Watching for suspicious domain connections via VirusTotal... Press Ctrl+C to stop.")
    try:
        run_behavior_protection()
        ips = get_active_ips()
        for ip in ips:
            domain = resolve_domain(ip)
            if domain:
                score = get_domain_report(domain)
                print(f"🔎 {domain} ({ip}) | Malicious score: {score}")
                log_event("Checked", ip, domain, score)
                if score >= 5:
                    toast.show_toast("AI Hunter – Malicious Domain ⚠️",
                                     f"{domain} flagged with score {score}", duration=5)
                    block_ip(ip)
                    log_event("Blocked", ip, domain, score)
        print("✅ Domain scan finished.")
    # <-- AQUI va el envío de correo, DENTRO del try:
        from email_reporter import send_threat_report
        send_threat_report(
            subject="🚨 AI Hunter – Threat Alert",
            body="Se detectó una amenaza que no se pudo bloquear automáticamente. Requiere atención.",
            attachments=["threat_report.txt"]
        )

    except KeyboardInterrupt:
        print("Stopped.")
