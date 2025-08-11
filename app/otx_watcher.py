from dotenv import load_dotenv
import os
import psutil
import time
import requests
from win10toast import ToastNotifier
import subprocess

# Load env vars
load_dotenv()
OTX_API_KEY = os.getenv("ALIENVAULT_API_KEY")
toast = ToastNotifier()

BLOCKED_IPS = set()

def fetch_otx_ips():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"❌ Failed to fetch OTX data: {response.status_code}")
            return set()
        data = response.json()
        ips = set()
        for pulse in data.get("results", []):
            for i in pulse.get("indicators", []):
                if i.get("type") == "IPv4":
                    ips.add(i["indicator"])
        print(f"✅ Fetched {len(ips)} known bad IPs from OTX pulses.")
        return ips
    except Exception as e:
        print(f"❌ Exception during OTX fetch: {e}")
        return set()

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
        print(f"🛑 Blocked IP: {ip}")
        toast.show_toast("AI Hunter – OTX Blocked 🚫", f"Blocked malicious IP: {ip}", duration=5)
        BLOCKED_IPS.add(ip)
    except Exception as e:
        print(f"❌ Failed to block {ip}: {e}")

def get_active_ips():
    ips = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.status == 'ESTABLISHED':
            ip = conn.raddr.ip
            if ':' not in ip:
                ips.add(ip)
    return ips

def main():
    print(f"🔐 Loaded OTX API Key: {OTX_API_KEY[:6]}**********")
    print("🛡️  Watching for OTX pulse threats...")

    otx_ips = fetch_otx_ips()
    print(f"🔎 IPs to watch: {otx_ips}")

    active_ips = get_active_ips()
    print(f"📡 Active connections: {active_ips}")

    for ip in active_ips:
        if ip in otx_ips:
            block_ip(ip)

    print("✅ OTX scan complete.")

if __name__ == "__main__":
    main()

def scan_once() -> int:
    """One pass: fetch OTX pulse IPs and block any currently connected."""
    blocked = 0
    otx_ips = fetch_otx_ips()
    print(f"🔎 IPs to watch: {otx_ips}")
    active = get_active_ips()
    print(f"📡 Active connections: {active}")
    for ip in active:
        if ip in otx_ips:
            block_ip(ip)
            blocked += 1
    print("✅ OTX scan complete.")
    return blocked

