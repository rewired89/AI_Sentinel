import json
import os
import psutil
import time
import subprocess
from win10toast import ToastNotifier

RECHECK_INTERVAL = 10  # seconds
BLOCKED_LOG = "data/blocked_ips_log.json"
RECONNECT_LOG = "data/reconnection_attempts_log.json"

toast = ToastNotifier()

# Load blocked IPs
if os.path.exists(BLOCKED_LOG):
    with open(BLOCKED_LOG, "r") as f:
        blocked_ips = set(json.load(f))
else:
    blocked_ips = set()

# Load previous reconnections
if os.path.exists(RECONNECT_LOG):
    with open(RECONNECT_LOG, "r") as f:
        reconnect_attempts = json.load(f)
else:
    reconnect_attempts = []

def log_reconnection(ip):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    reconnect_attempts.append({"ip": ip, "timestamp": timestamp})
    with open(RECONNECT_LOG, "w") as f:
        json.dump(reconnect_attempts, f, indent=2)

def reapply_block(ip):
    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=Reblock_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                   capture_output=True, text=True)
    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=Reblock_{ip}_out", "dir=out", "action=block", f"remoteip={ip}"],
                   capture_output=True, text=True)

def monitor():
    print("👁️  Monitoring for reconnection attempts from blocked IPs... Press Ctrl+C to stop.")
    try:
        while True:
            active_ips = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.status == 'ESTABLISHED':
                    ip = conn.raddr.ip
                    if ':' not in ip:  # Skip IPv6
                        active_ips.add(ip)

            for ip in active_ips:
                if ip in blocked_ips:
                    print(f"🚨 Reconnection attempt from blocked IP: {ip}")
                    log_reconnection(ip)
                    reapply_block(ip)
                    toast.show_toast(
                        "AI Sentinel Alert – Reconnection ⚠️",
                        f"Blocked IP tried to reconnect: {ip}",
                        duration=5
                    )

            time.sleep(RECHECK_INTERVAL)

    except KeyboardInterrupt:
        print("Stopped.")

if __name__ == "__main__":
    monitor()
