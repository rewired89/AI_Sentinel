import threading
from detect_anomalies import main as run_malware_watcher
from ip_watcher import main as run_ip_watcher
from otx_watcher import main as run_otx_watcher
from domain_watcher import main as run_domain_watcher
import time

print("🚀 AI Hunter is now running...")

# Lanzar todos los módulos en hilos separados
threads = []

threads.append(threading.Thread(target=run_malware_watcher))
threads.append(threading.Thread(target=run_ip_watcher))
threads.append(threading.Thread(target=run_otx_watcher))
threads.append(threading.Thread(target=run_domain_watcher))

# Iniciar todos los hilos
for t in threads:
    t.start()

# Esperar a que terminen
for t in threads:
    t.join()

print("✅ All scans completed. AI Hunter stopped.")
