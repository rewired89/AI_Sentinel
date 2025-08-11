import psutil, time

procs = list(psutil.process_iter(['pid','name','cmdline']))
for p in procs:
    try: p.cpu_percent(None)
    except Exception: pass

time.sleep(0.5)

rows = []
for p in procs:
    try:
        cpu = p.cpu_percent(None)
        cmd = " ".join(p.info.get('cmdline') or [])
        rows.append((cpu, p.info.get('pid'), p.info.get('name'), cmd))
    except Exception:
        pass

rows.sort(reverse=True)
for cpu,pid,name,cmd in rows[:15]:
    print(f"{cpu:5.1f}%  PID={pid:<6} {name:<15} {cmd[:140]}")
