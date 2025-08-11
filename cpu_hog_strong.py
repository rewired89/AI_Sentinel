# cpu_hog_strong.py
import time, math, os

print(f"[hog] PID {os.getpid()} starting")
end = time.time() + 90  # run for ~90 seconds
x = 0.0001
while time.time() < end:
    x = math.sqrt(x * x + 1.23456789)
print(f"[hog] PID {os.getpid()} done")
